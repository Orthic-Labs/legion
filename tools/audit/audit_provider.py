"""Audit provider adapter (G4 of the Membrane unified architecture).

Exposes the typed audit store to the planner as a ``ContextProvider``-shaped
producer: it reads ``AuditFindingV1`` records from
``<repo>/.audit/audit/findings.jsonl`` and emits one ``ContextCandidate`` per
``status == open`` finding. Resolved / dismissed / superseded findings are
deliberately suppressed — they do not rank as active findings (G4 acceptance
rule #3) and they MUST NOT surface to the planner.

The adapter owns ONLY admission; the planner owns ranking, deduplication, and
budget enforcement. Capability federation wires this adapter through the central
catalog; G4 keeps the boundary narrow on purpose.

Identity passthrough: candidate IDs are the *finding IDs* from the typed
store, so a planner citation, a receipt, and a finding record refer to the
exact same stable string. The ``audit:rule:`` prefix already used in the G1
fixtures stays the canonical planner-facing handle.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from pathlib import Path

from audit_store import AuditStore, ACTIVE_STATUSES, SCHEMA_VERSION  # same dir

# Layer assignment: audit findings are diagnostics — they ride layer 4 (skills /
# operating context). The value comes from the unified architecture, not from
# the planner code, so it lives next to the provider.
AUDIT_CANDIDATE_LAYER = 4
PROVIDER_NAME = "audit"
AUDIT_SOURCE_KIND = "audit_finding"
DEFAULT_TRUST_CLASS = "agent_verified"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _estimate_tokens(loci: list[dict[str, Any]]) -> int:
    """Conservative token estimate from the primary locus.

    The provider returns a single block per finding — its block text is the
    evidence locus pointer and the human-readable title. The budget signal is
    intentionally light; the planner caps this against its own ceiling.
    """
    if not loci:
        return 0
    primary = loci[0]
    path = str(primary.get("path", ""))
    return max(1, (len(path) // 4) + 32)


def _risk_score(record: dict[str, Any]) -> float:
    """Provider score in [0,1] — combines severity rank and confidence.

    The planner may re-rank via scoreComponents; this is the raw signal only.
    """
    sev = record.get("severity", "medium")
    confidence = float(record.get("confidence", 1.0))
    sev_map = {"info": 0.2, "low": 0.4, "medium": 0.6, "high": 0.8, "critical": 1.0}
    base = sev_map.get(sev, 0.5)
    return round(min(1.0, max(0.0, 0.5 * base + 0.5 * confidence)), 3)


def _source_ref(record: dict[str, Any]) -> str:
    """Stable ``sourceRef`` — mirrors the G1 fixture convention (``audit://…``)."""
    rule = record["provenance"].get("ruleId") or record["provenance"].get("name") or "unknown"
    primary = record["evidenceLoci"][0]
    suffix = f"@{primary['path']}:{primary['startLine']}-{primary['endLine']}"
    return f"audit://rule:{rule}{suffix}"


def _candidate_text(record: dict[str, Any]) -> str:
    primary = record["evidenceLoci"][0]
    return (
        f"finding={record['id']} status={record['status']} severity={record['severity']} "
        f"category={record['category']} locus={primary['path']}:{primary['startLine']}-{primary['endLine']} "
        f"title={record['title']}"
    )


def _resolver_text(record: dict[str, Any]) -> str:
    return f"audit resolve {record['id']}"


@dataclass
class ProviderContext:
    """Minimal planner-facing context; deliberately narrow.

    ``scope`` enforces an optional repository filter — out-of-scope findings
    MUST NOT produce candidates (cross-root isolation; G4 acceptance).
    ``audit_generation`` is informational; it is also embedded into the
    freshness metadata so receipts can cite which generation produced the
    findings.
    """

    repo_root: str | Path
    repository_id: str
    audit_generation: str = ""
    scope: str | None = None  # str(repo_root) by convention

    def __post_init__(self) -> None:
        self.repo_root = Path(self.repo_root).resolve()
        if self.scope is None:
            self.scope = str(self.repo_root)


@dataclass
class Candidate:
    """Shape-compatible with ``ContextCandidateSet.candidates[*]``."""

    id: str
    layer: int
    sourceKind: str
    sourceRef: str
    sourceHash: str
    trustClass: str
    instructionPolicy: str
    providerScore: float
    scoreComponents: dict[str, float]
    estimatedTokens: int
    protected: bool
    exact: bool
    recoverable: bool
    resolver: str
    text: str


@dataclass
class CandidateSet:
    """Subset of ``ContextCandidateSet`` needed for audit-provider consumers.

    The full schema is owned by the planner — the provider emits enough fields
    for the planner to round-trip the candidates, but does not mint a
    ``traceId`` or ``providerCeiling`` (those are planner-level concerns).
    """

    provider: str
    freshness: dict[str, Any]
    candidates: list[Candidate]


def _record_to_candidate(record: dict[str, Any], freshness_indexed_at: str) -> Candidate:
    primary_hash = record["evidenceLoci"][0]["contentSha256"]
    base_score = _risk_score(record)
    return Candidate(
        id=record["id"],
        layer=AUDIT_CANDIDATE_LAYER,
        sourceKind=AUDIT_SOURCE_KIND,
        sourceRef=_source_ref(record),
        sourceHash=primary_hash,
        trustClass=DEFAULT_TRUST_CLASS,
        instructionPolicy="data_only",
        providerScore=base_score,
        scoreComponents={
            "severity": float(record.get("severity_rank", base_score)),
            "confidence": float(record.get("confidence", 1.0)),
            "freshness": 1.0,  # active findings are by definition current per scope
        },
        estimatedTokens=_estimate_tokens(record["evidenceLoci"]),
        protected=False,
        exact=False,
        recoverable=True,
        resolver=_resolver_text(record),
        text=_candidate_text(record),
    )


# severity_rank is derived from the enum for scoreComponents' use:
#   info=0, low=1, medium=2, high=3, critical=4  => /4 in [0,1]
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _decorate(record: dict[str, Any]) -> dict[str, Any]:
    record = dict(record)
    record["severity_rank"] = _SEVERITY_RANK.get(record.get("severity", "medium"), 2) / 4.0
    return record


class AuditProvider:
    """Read-only adapter over :class:`AuditStore` for planner admission."""

    def __init__(self, ctx: ProviderContext) -> None:
        self.ctx = ctx
        self._store = AuditStore(ctx.repo_root)
        self._indexed_at = ctx.audit_generation and _now_iso() or _now_iso()

    # ── identity helpers exposed for tests and the planner ─────────
    @staticmethod
    def candidate_layer() -> int:
        return AUDIT_CANDIDATE_LAYER

    @staticmethod
    def provider_name() -> str:
        return PROVIDER_NAME

    # ── primary API ─────────────────────────────────────────────────
    def list_open_findings(self, *, repository_id: str | None = None) -> list[dict[str, Any]]:
        """All findings whose status is currently ``open``.

        ``repositoryId`` defaults to the provider context's value; if a
        caller supplies a different value, the provider returns ``[]`` —
        cross-root isolation is enforced here, not later.
        """
        if repository_id is None:
            repository_id = self.ctx.repository_id
        if repository_id != self.ctx.repository_id:
            return []
        return self._store.active(repository_id=repository_id)

    def produce_candidate_set(
        self,
        task: str | None = None,
        scope: str | None = None,
        *,
        repository_id: str | None = None,
    ) -> dict[str, Any]:
        """Produce a planner-shaped candidate set for ``task`` over ``scope``.

        ``task`` is advisory metadata that the planner stamps into the
        ``ContextCandidateSet.task`` field. ``scope`` overrides the provider
        context's scope for this call; out-of-scope requests return an empty
        set with no candidates.
        """
        effective_scope = scope if scope is not None else self.ctx.scope
        if effective_scope != self.ctx.scope:
            return self._empty_set(task or "")
        records = self.list_open_findings(repository_id=repository_id)
        candidates = [
            _record_to_candidate(_decorate(r), self._indexed_at)
            for r in records
        ]
        return self._wrap(candidates, task or "")

    # ── internal helpers ───────────────────────────────────────────
    def _empty_set(self, task: str) -> dict[str, Any]:
        return {
            "provider": PROVIDER_NAME,
            "freshness": self._freshness(),
            "candidates": [],
            "omissions": [],
        }

    def _freshness(self) -> dict[str, Any]:
        return {
            "revision": self.ctx.audit_generation or "audit-default",
            "indexedAt": self._indexed_at,
            "stale": False,
        }

    def _wrap(self, candidates: list[Candidate], task: str) -> dict[str, Any]:
        return {
            "provider": PROVIDER_NAME,
            "freshness": self._freshness(),
            "candidates": [as_dict(c) for c in candidates],
            "task": task,
        }


def as_dict(candidate: Candidate) -> dict[str, Any]:
    """Adapter for ``dataclasses.asdict`` — explicit so callers don't import it."""
    return {
        "id": candidate.id,
        "layer": candidate.layer,
        "sourceKind": candidate.sourceKind,
        "sourceRef": candidate.sourceRef,
        "sourceHash": candidate.sourceHash,
        "trustClass": candidate.trustClass,
        "instructionPolicy": candidate.instructionPolicy,
        "providerScore": candidate.providerScore,
        "scoreComponents": dict(candidate.scoreComponents),
        "estimatedTokens": candidate.estimatedTokens,
        "protected": candidate.protected,
        "exact": candidate.exact,
        "recoverable": candidate.recoverable,
        "resolver": candidate.resolver,
        "text": candidate.text,
    }
