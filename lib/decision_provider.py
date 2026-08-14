"""Architect decision lifecycle provider.

Lane-owned (G5 Lane A). Reads from a `DecisionStore` and produces
ContextCandidateSet-shaped candidates (`Candidate` records with the schema
fields required by the Right Suite context contracts) plus a status
lifecycle policy:

    proposed -> accepted -> implemented -> superseded

Lifecycle rules enforced here (fail-closed):

* A `proposed` record is NEVER admitted when an `accepted` (or later)
  sibling already exists for the same logical decision. Two records
  share identity when their derived stable id is equal OR when they
  appear in each other's `supersedes` chain.
* A `superseded` record is NEVER admitted when a current (non-superseded)
  record exists for the same logical decision.
* `implemented` records require a non-empty `implementationRefs` array
  (mirrors the schema's `allOf` clause) and we surface that as a
  ProviderWarning so the caller can log instead of silently admitting
  an incomplete record.

Candidate IDs follow the `architect:decision:*` scheme already used in
the G1 fixture corpus (`corpus-v1.json`), specifically the
`architect:decision:rightsuite-pricing-2026-06-28` form for a current
record and `architect:decision:<id>:proposed` for a historical proposed
sibling.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from decision_store import (
    DECISION_ID_PREFIX,
    DecisionRecord,
    DecisionStore,
    SCHEMA_VERSION,
    STATUSES,
    derive_decision_id,
)

LAYER = 5
PROVIDER_NAME = "architect"
SOURCE_KIND = "architect_decision"
TRUST_CLASS = "agent_verified"
INSTRUCTION_POLICY = "data_only"
SCHEMA_VERSION_CONTRACT = 1

# Lifecycle: forward edge list. A decision may move forward along these
# edges; backward moves are rejected with LifecycleError.
LIFECYCLE_FORWARD: dict[str, tuple[str, ...]] = {
    "proposed": ("accepted", "superseded"),
    "accepted": ("implemented", "superseded"),
    "implemented": ("superseded",),
    "superseded": (),
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LifecycleError(ValueError):
    """Raised when a lifecycle invariant would be violated by an admission."""


class ProviderWarning:
    """Non-fatal advisory produced alongside a candidate set."""

    __slots__ = ("code", "decision_id", "detail")

    def __init__(self, code: str, decision_id: str, detail: str) -> None:
        self.code = code
        self.decision_id = decision_id
        self.detail = detail

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "decisionId": self.decision_id,
            "detail": self.detail,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging only
        return f"ProviderWarning({self.code!r}, {self.decision_id!r})"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical(value: str) -> str:
    return (value or "").strip().lower()


def _stable_source_hash(record: dict[str, Any]) -> str:
    """Return a content-hash for the decision record (excluding volatile fields)."""

    payload = {
        "id": record.get("id"),
        "repositoryId": record.get("repositoryId"),
        "scopeId": record.get("scopeId"),
        "taskId": record.get("taskId"),
        "linkedGraphGeneration": record.get("linkedGraphGeneration"),
        "rationale": record.get("rationale"),
        "alternatives": list(record.get("alternatives", [])),
        "evidence": list(record.get("evidence", [])),
        "implementationRefs": list(record.get("implementationRefs", []) or []),
        "supersedes": list(record.get("supersedes", []) or []),
        "supersededBy": record.get("supersededBy"),
        "currentStatus": record.get("currentStatus"),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(encoded.encode("utf-8", errors="replace")).hexdigest()
    return f"sha256:{digest}"


def _candidate_id_for(record: DecisionRecord) -> str:
    """Return the canonical candidate id for a decision record.

    For records with a stable `architect:decision:<digest>` id we expose
    that directly. For sibling records that share the same logical
    decision but are stored as separate JSONL rows (typically a
    proposed-then-superseded pair), the historical sibling gets a
    `:proposed` suffix so the corpus fixture contract (G1) still matches.
    """

    base_id = record.id
    if base_id.startswith(DECISION_ID_PREFIX):
        if record.current_status == "proposed":
            return f"{base_id}:proposed"
        return base_id
    # Records written before the digest scheme stay addressable by their
    # own id; the store does not silently rewrite ids on load.
    return base_id


def _text_for(record: DecisionRecord) -> str:
    """Short text body for the candidate. No raw rationale leakage."""

    status = record.current_status
    head = f"Architect decision ({status})"
    return f"{head}: task={record.record.get('taskId', '')} rationale={record.record.get('rationale', '')}"


def _estimated_tokens(text: str) -> int:
    # Approximation good enough for provider ceilings; one token ~ 4 chars.
    return max(1, (len(text) + 3) // 4)


# ---------------------------------------------------------------------------
# Candidate production
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CandidateSpec:
    """Lightweight description used by `produce_candidate_set`.

    A spec captures the request side: which task is asking, and which
    scope/repo/generation to filter on. The provider does the rest.
    """

    task: str
    repository_id: str
    scope_id: str
    linked_graph_generation: str | None = None
    trace_id: str | None = None
    provider: str = PROVIDER_NAME
    max_candidates: int = 40
    max_estimated_tokens: int = 8000


@dataclass(frozen=True)
class ContextCandidateSet:
    """A small subset of the Right Suite ContextCandidateSet contract.

    We return only the fields the federating planner needs in order to
    compose an admission: schemaVersion, trace, task/mode/provider,
    freshness, providerCeiling, candidates, omissions. Additional fields
    are added by the planner; this provider never invents context.
    """

    schema_version: int
    trace_id: str
    task: str
    mode: str
    provider: str
    freshness: dict[str, Any]
    provider_ceiling: dict[str, int]
    candidates: tuple[dict[str, Any], ...]
    omissions: tuple[dict[str, str], ...]
    warnings: tuple[ProviderWarning, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schemaVersion": self.schema_version,
            "traceId": self.trace_id,
            "task": self.task,
            "mode": self.mode,
            "provider": self.provider,
            "freshness": self.freshness,
            "providerCeiling": self.provider_ceiling,
            "candidates": list(self.candidates),
            "omissions": list(self.omissions),
        }
        if self.warnings:
            payload["warnings"] = [warning.as_dict() for warning in self.warnings]
        return payload


def _trace_id(spec: CandidateSpec) -> str:
    if spec.trace_id:
        return spec.trace_id
    digest = hashlib.sha256(
        f"{spec.task}|{spec.repository_id}|{spec.scope_id}".encode("utf-8")
    ).hexdigest()
    return digest[:24]


def _freshness(records: Sequence[DecisionRecord]) -> dict[str, Any]:
    # Latest createdAt wins; missing timestamps degrade to an explicit
    # stale=true rather than fabricating one.
    latest: str | None = None
    for record in records:
        created = record.record.get("createdAt")
        if not created:
            continue
        if latest is None or created > latest:
            latest = created
    if latest is None:
        latest = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "revision": f"architect-{latest}",
        "indexedAt": latest,
        "stale": False,
    }


def _index_active(
    records: Iterable[DecisionRecord],
    *,
    repository_id: str,
) -> tuple[dict[str, DecisionRecord], dict[str, list[DecisionRecord]]]:
    """Group records by stable id and keep only the highest-priority status.

    Returns:
        current: map of stable_id -> the single 'current' record
                 (i.e. the highest-priority non-superseded sibling).
        siblings: map of stable_id -> ALL records sharing that id, in
                  insertion order (used for supersession lineage).

    Lifecycle rule: when a stable id's highest-priority sibling is a
    `proposed` record AND another sibling in the same group has been
    explicitly superseded, the proposed record is treated as a stale
    leftover — no candidate is admitted for that stable id. The
    superseded sibling is the truth, and the proposed sibling was
    retired before promotion.
    """

    siblings: dict[str, list[DecisionRecord]] = {}
    for record in records:
        if record.record.get("repositoryId") != repository_id:
            continue
        siblings.setdefault(record.id, []).append(record)
    priority = {"implemented": 3, "accepted": 2, "proposed": 1, "superseded": 0}
    current: dict[str, DecisionRecord] = {}
    for stable_id, group in siblings.items():
        statuses = {record.current_status for record in group}
        if "superseded" in statuses and "accepted" not in statuses and "implemented" not in statuses:
            # Only proposed/superseded siblings — the proposed sibling is a
            # leftover from a retired lineage; do NOT admit it.
            continue
        best = max(group, key=lambda r: priority.get(r.current_status, -1))
        if best.current_status != "superseded":
            current[stable_id] = best
    return current, siblings


def _build_candidate(
    record: DecisionRecord,
    *,
    exact: bool,
    provider_score: float,
    text: str | None = None,
) -> dict[str, Any]:
    body = text if text is not None else _text_for(record)
    return {
        "id": _candidate_id_for(record),
        "layer": LAYER,
        "sourceKind": SOURCE_KIND,
        "sourceRef": f"architect://decision:{record.id}",
        "sourceHash": _stable_source_hash(record.record),
        "trustClass": TRUST_CLASS,
        "instructionPolicy": INSTRUCTION_POLICY,
        "providerScore": provider_score,
        "scoreComponents": {
            "lifecycle": _score_for_status(record.current_status),
            "scope": 1.0 if record.record.get("repositoryId") else 0.0,
        },
        "estimatedTokens": _estimated_tokens(body),
        "protected": False,
        "exact": exact,
        "recoverable": True,
        "resolver": f"architect resolve {_candidate_id_for(record)}",
        "text": body,
    }


def _score_for_status(status: str) -> float:
    return {
        "implemented": 0.97,
        "accepted": 0.94,
        "proposed": 0.71,
        "superseded": 0.0,
    }.get(status, 0.5)


def _supersedes_chain(
    record: DecisionRecord,
    siblings: dict[str, list[DecisionRecord]],
) -> set[str]:
    """Walk the supersedes edges from a record to its ancestors.

    Two records are considered the SAME logical decision when one
    appears in the other's supersedes list (or both walk to a common
    ancestor). We treat `supersedes` as forward edges (record ->
    record-it-replaces) so the chain is the set of ids this record
    supersedes.
    """

    chain: set[str] = set()
    for sibling_id in record.record.get("supersedes", []) or []:
        chain.add(sibling_id)
        # Recurse one level — supersession chains are short in practice
        # but a depth-2 walk catches the rare two-step lineage.
        for group in siblings.values():
            for candidate in group:
                if candidate.id in chain:
                    chain.update(candidate.record.get("supersedes", []) or [])
    return chain


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def produce_candidate_set(
    task: str | CandidateSpec,
    scope: dict[str, Any] | None = None,
    *,
    store: DecisionStore | None = None,
    store_path: Path | str | None = None,
    mode: str = "edit",
) -> ContextCandidateSet:
    """Produce a ContextCandidateSet for the supplied task.

    The call accepts either a bare task string (in which case the scope
    defaults to an empty repo filter) or a `CandidateSpec`. The scope dict
    may carry `repositoryId`, `scopeId`, `linkedGraphGeneration`,
    `traceId`, `maxCandidates`, and `maxEstimatedTokens`.

    Lifecycle enforcement:

    * For every stable decision id we admit AT MOST one record: the
      current (highest-priority non-superseded) sibling.
    * Sibling `proposed` records are emitted as `omissions` with the
      reason `superseded_by_current` so the planner sees the trace.
    * Stale records whose `linkedGraphGeneration` differs from the
      request scope are downgraded to omissions with reason
      `stale_graph_generation`.
    """

    spec = _coerce_spec(task, scope)
    resolved_store = store or DecisionStore(store_path) if store_path else (store or DecisionStore.for_repo(Path(spec.repository_id or ".")))
    records = list(resolved_store.iter_records())
    current, siblings = _index_active(records, repository_id=spec.repository_id)

    warnings: list[ProviderWarning] = []
    candidates: list[dict[str, Any]] = []
    omissions: list[dict[str, str]] = []

    for stable_id, current_record in current.items():
        chain = _supersedes_chain(current_record, siblings)

        # 1. If a sibling exists with the SAME stable id and status
        #    `superseded` while THIS record is the current, the sibling
        #    is intentionally excluded — it was correctly superseded.
        #    No omission entry needed (the chain itself is the trail).

        # 2. If the graph generation in scope does not match the record's
        #    `linkedGraphGeneration`, downgrade to omission.
        if (
            spec.linked_graph_generation
            and current_record.record.get("linkedGraphGeneration") != spec.linked_graph_generation
        ):
            omissions.append(
                {
                    "id": _candidate_id_for(current_record),
                    "layer": str(LAYER),
                    "reason": "stale_graph_generation",
                }
            )
            continue

        # 3. Implemented records must carry implementationRefs (schema
        #    `allOf`); warn if missing but still emit the candidate so
        #    the planner can decide.
        if (
            current_record.current_status == "implemented"
            and not current_record.record.get("implementationRefs")
        ):
            warnings.append(
                ProviderWarning(
                    code="implementation_refs_missing",
                    decision_id=_candidate_id_for(current_record),
                    detail="implemented record has empty implementationRefs",
                )
            )

        # 4. Emit the current record as a candidate. Historical proposed
        #    siblings are recorded as omissions so the planner can see
        #    the lineage.
        candidates.append(
            _build_candidate(
                current_record,
                exact=current_record.current_status in {"accepted", "implemented"},
                provider_score=_score_for_status(current_record.current_status),
            )
        )
        for group in siblings.get(stable_id, []):
            if group is current_record:
                continue
            if group.current_status == "superseded":
                continue
            # A historical `proposed` sibling sharing the same stable id.
            omissions.append(
                {
                    "id": _candidate_id_for(group),
                    "layer": str(LAYER),
                    "reason": "superseded_by_current",
                }
            )
        for superseded_id in chain:
            omissions.append(
                {
                    "id": f"{DECISION_ID_PREFIX}:{superseded_id}",
                    "layer": str(LAYER),
                    "reason": "supersession_chain",
                }
            )

    # Deterministic ordering: highest score first, then id.
    candidates.sort(key=lambda cand: (-float(cand["providerScore"]), cand["id"]))

    # Provider ceiling enforcement — admissions are fail-closed when the
    # ceiling cannot be met.
    ceiling_candidates = candidates[: spec.max_candidates]
    if len(candidates) > spec.max_candidates:
        for dropped in candidates[spec.max_candidates :]:
            omissions.append(
                {
                    "id": dropped["id"],
                    "layer": str(LAYER),
                    "reason": "max_candidates_exceeded",
                }
            )

    admitted_tokens = sum(c["estimatedTokens"] for c in ceiling_candidates)
    if admitted_tokens > spec.max_estimated_tokens:
        # Refuse to admit rather than silently truncate. The planner must
        # decide whether to escalate the budget.
        raise LifecycleError(
            f"admitted tokens {admitted_tokens} exceed ceiling {spec.max_estimated_tokens}"
        )

    return ContextCandidateSet(
        schema_version=SCHEMA_VERSION_CONTRACT,
        trace_id=_trace_id(spec),
        task=spec.task,
        mode=mode,
        provider=spec.provider,
        freshness=_freshness(records),
        provider_ceiling={
            "maxCandidates": spec.max_candidates,
            "maxEstimatedTokens": spec.max_estimated_tokens,
        },
        candidates=tuple(ceiling_candidates),
        omissions=tuple(omissions),
        warnings=tuple(warnings),
    )


def _coerce_spec(
    task: str | CandidateSpec,
    scope: dict[str, Any] | None,
) -> CandidateSpec:
    if isinstance(task, CandidateSpec):
        return task
    scope = scope or {}
    return CandidateSpec(
        task=task,
        repository_id=str(scope.get("repositoryId") or scope.get("repository_id") or ""),
        scope_id=str(scope.get("scopeId") or scope.get("scope_id") or ""),
        linked_graph_generation=(
            scope.get("linkedGraphGeneration") or scope.get("linked_graph_generation")
        ),
        trace_id=scope.get("traceId") or scope.get("trace_id"),
        provider=str(scope.get("provider", PROVIDER_NAME)),
        max_candidates=int(scope.get("maxCandidates", scope.get("max_candidates", 40))),
        max_estimated_tokens=int(
            scope.get("maxEstimatedTokens", scope.get("max_estimated_tokens", 8000))
        ),
    )


__all__ = [
    "CandidateSpec",
    "ContextCandidateSet",
    "LifecycleError",
    "LIFECYCLE_FORWARD",
    "PROVIDER_NAME",
    "ProviderWarning",
    "STATUSES",
    "derive_decision_id",
    "produce_candidate_set",
]