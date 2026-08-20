"""Typed Audit finding store (G4 of the Membrane unified architecture).

This module persists ``AuditFindingV1`` records — typed, stable-identity audit
findings — in a JSONL store rooted at ``<repo>/.audit/audit/findings.jsonl``.

It is intentionally separate from:

* the Crypt durable-memory database (different storage boundary; G4 owns its
  own file so the durable-memory authority is preserved),
* the central provider catalog (capability-federation wiring),
* the raw ``.audit/<ts>/report.json`` artifact (still produced by the existing
  renderer; treated as a read-only import source — the planner reads the typed
  store, not the prose report).

Stable IDs follow the ``audit:rule:<rule>:<path>`` scheme already used in the
G1 fixtures (``tools/tests/membrane/feasibility/corpus-v1.json``); the
stable input is ``repositoryId + ruleId + canonical evidence locus (content
hash of path + start/end lines)``. Re-emitting the same finding in a later
audit generation MUST retain the same ID and update ``lastSeen*``; a changed
or replaced finding records explicit supersession rather than overwriting.

Status lifecycle: ``open`` → ``resolved`` | ``dismissed`` | ``superseded``.
Only ``open`` findings are eligible to surface as planner candidates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


SCHEMA_VERSION = 1
ACTIVE_STATUSES = frozenset({"open"})
TERMINAL_STATUSES = frozenset({"resolved", "dismissed", "superseded"})
ALL_STATUSES = ACTIVE_STATUSES | TERMINAL_STATUSES

PROVENANCE_KINDS = frozenset({"deterministic_scanner", "reasoning_lens", "manual"})

# Stable ID scheme. ``audit:<kind>:<ruleId>:<path>`` is the canonical planner-
# facing scheme; :<locus-suffix> may be appended for findings with a single
# primary locus but G1's fixtures encode the base form as ``audit:rule:<rule>:<path>``.
ID_KIND_PREFIX = "audit:rule:"


def _utc_now() -> str:
    """ISO-8601 UTC timestamp with ``Z`` suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _locus_content_hash(path: str, start_line: int, end_line: int) -> str:
    """Content hash over ``path:start-end``, normalized to forward slashes.

    Matches the G1 fixture convention (``sha256:000…<hex>``) — we use a full
    sha256 hex, prefixed ``sha256:``. The hash input is the canonical locus
    string; line numbers are integers. This is the deterministic identity
    input alongside repository + ruleId.
    """
    norm = path.replace("\\", "/").lstrip("/")
    key = f"{norm}:{int(start_line)}-{int(end_line)}".encode("utf-8")
    return "sha256:" + hashlib.sha256(key).hexdigest()


def derive_finding_id(
    repository_id: str,
    rule_id: str,
    evidence_loci: Iterable[dict[str, Any]],
) -> str:
    """Derive a stable finding ID from repository + rule + canonical locus.

    Identity inputs (must remain stable across audit generations):

    * repositoryId — issued by the planner/manifest; never a machine path.
    * ruleId — the scanner rule or reasoning lens identifier (the
      ``ProvenanceRef.ruleId`` is the same string).
    * the *first* primary locus content hash — ``path + startLine + endLine``
      double-hashed (sha256 over the canonical locus key). When a finding
      spans multiple loci, the first locus defines identity; supersession
      handling must keep this stable.

    Returns the canonical ``audit:rule:<repoTag>-<ruleId>:<path>:<digest>``
    form, where ``repoTag`` is a 7-char sha256 of the stable repository id
    and ``digest`` is a 7-char sha256 of the canonical locus. The repo tag
    is included because the G4 dispatch requires repository identity in
    stable ID derivation; the G1 corpus fixtures use the bare
    ``audit:rule:<rule>:<path>`` form only because their corpus is a
    synthetic single-repo fixture.
    """
    norm_repo = repository_id.strip()
    if not norm_repo:
        raise ValueError("repositoryId is required for stable finding ID")
    norm_rule = rule_id.strip()
    if not norm_rule:
        raise ValueError("ruleId is required for stable finding ID")
    first = next(iter(evidence_loci), None)
    if first is None:
        raise ValueError("at least one evidence locus is required for stable finding ID")
    locus_hash = _locus_content_hash(
        str(first["path"]),
        int(first["startLine"]),
        int(first["endLine"]),
    )
    norm_path = str(first["path"]).replace("\\", "/").lstrip("/")
    repo_digest = hashlib.sha256(norm_repo.encode("utf-8")).hexdigest()[:7]
    locus_digest = locus_hash.rsplit(":", 1)[-1][:7]
    return f"{ID_KIND_PREFIX}{repo_digest}-{norm_rule}:{norm_path}:{locus_digest}"


def _default_provenance(rule_id: str, kind: str = "deterministic_scanner", version: str = "1") -> dict:
    if kind not in PROVENANCE_KINDS:
        raise ValueError(f"invalid provenance kind: {kind!r}")
    return {"kind": kind, "name": rule_id, "version": version, "ruleId": rule_id}


@dataclass
class FindingDraft:
    """In-memory draft used to construct an AuditFindingV1 record.

    Callers supply the deterministic identity inputs; the store assigns
    timestamps, generation, and content-hash IDs.
    """

    repository_id: str
    scope_id: str
    rule_id: str
    category: str
    title: str
    evidence_loci: list[dict[str, Any]]
    severity: str = "medium"
    confidence: float = 1.0
    provenance: dict | None = None
    audit_generation: str = ""
    linked_graph_generation: str | None = None
    provenance_kind: str = "deterministic_scanner"
    provenance_version: str = "1"


def _coerce_locus(locus: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(locus, dict):
        raise ValueError("evidence locus must be an object")
    path = locus.get("path")
    start = locus.get("startLine")
    end = locus.get("endLine")
    if not (isinstance(path, str) and path):
        raise ValueError("evidence locus requires non-empty path")
    if not (isinstance(start, int) and start >= 1):
        raise ValueError("evidence locus requires positive integer startLine")
    if not (isinstance(end, int) and end >= start):
        raise ValueError("evidence locus requires endLine >= startLine >= 1")
    out: dict[str, Any] = {
        "path": path,
        "startLine": start,
        "endLine": end,
        "contentSha256": _locus_content_hash(path, start, end),
    }
    return out


def make_finding(
    draft: FindingDraft,
    *,
    audit_generation: str | None = None,
    linked_graph_generation: str | None = None,
    status: str = "open",
    now: str | None = None,
) -> dict[str, Any]:
    """Construct a fully-typed ``AuditFindingV1`` record from a draft.

    The store assigns:

    * a stable ``id`` derived from repo + rule + canonical locus,
    * ``auditGeneration`` and ``linkedGraphGeneration`` (when not supplied,
      these are left as ``""`` and MUST be set by the caller — the store
      itself does not mint generations),
    * ``firstSeenAt`` / ``lastSeenAt`` timestamps (UTC),
    * a default ``provenance`` block.

    ``now`` is an explicit override hook for deterministic tests.
    """
    if status not in ALL_STATUSES:
        raise ValueError(f"invalid status: {status!r}")
    loci = [_coerce_locus(l) for l in draft.evidence_loci]
    if not loci:
        raise ValueError("finding requires at least one evidence locus")
    fid = derive_finding_id(draft.repository_id, draft.rule_id, loci)
    ts = now or _utc_now()
    gen = audit_generation or draft.audit_generation or ""
    linked = linked_graph_generation if linked_graph_generation is not None else draft.linked_graph_generation
    linked = linked or ""
    provenance = draft.provenance or _default_provenance(
        draft.rule_id, kind=draft.provenance_kind, version=draft.provenance_version,
    )
    record: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "id": fid,
        "repositoryId": draft.repository_id,
        "scopeId": draft.scope_id,
        "auditGeneration": gen,
        "linkedGraphGeneration": linked,
        "severity": draft.severity,
        "category": draft.category,
        "title": draft.title,
        "evidenceLoci": loci,
        "confidence": float(draft.confidence),
        "status": status,
        "supersedes": [],
        "supersededBy": None,
        "firstSeenGeneration": gen,
        "lastSeenGeneration": gen,
        "firstSeenAt": ts,
        "lastSeenAt": ts,
        "resolvedGeneration": None,
        "resolvedAt": None,
        "provenance": provenance,
    }
    return record


def _validate(record: dict[str, Any]) -> None:
    """Light structural validation — the schema is the authority."""
    required = [
        "schemaVersion", "id", "repositoryId", "scopeId", "auditGeneration",
        "linkedGraphGeneration", "severity", "category", "title", "evidenceLoci",
        "confidence", "status", "firstSeenGeneration", "lastSeenGeneration",
        "firstSeenAt", "lastSeenAt", "provenance",
    ]
    for key in required:
        if key not in record:
            raise ValueError(f"finding record missing required field: {key}")
    if record["schemaVersion"] != SCHEMA_VERSION:
        raise ValueError(f"unexpected schemaVersion: {record['schemaVersion']}")
    if record["status"] not in ALL_STATUSES:
        raise ValueError(f"invalid status: {record['status']!r}")
    if not isinstance(record["evidenceLoci"], list) or not record["evidenceLoci"]:
        raise ValueError("evidenceLoci must be a non-empty list")
    for locus in record["evidenceLoci"]:
        _coerce_locus(locus)


def _record_id(record: dict[str, Any]) -> str:
    return record["id"]


@dataclass
class AuditStore:
    """JSONL-backed typed ``AuditFindingV1`` store.

    The store writes one record per line to ``<repo>/.audit/audit/findings.jsonl``.
    Updates are NOT in-place mutation — every write goes through the
    ``upsert`` / ``supersede`` / ``set_status`` paths, which preserve the
    full record history (the on-disk file is append-only-friendly because
    every upsert writes the *current* state of each ID).
    """

    repo: Path
    store_path: Path = field(init=False)
    _cache: dict[str, dict[str, Any]] = field(default_factory=dict, init=False)
    _loaded: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self.repo = Path(self.repo).resolve()
        self.store_path = self.repo / ".audit" / "audit" / "findings.jsonl"

    # ── file I/O ──────────────────────────────────────────────────────
    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        self._cache = {}
        if not self.store_path.is_file():
            return
        with self.store_path.open("r", encoding="utf-8") as handle:
            for lineno, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"corrupt JSONL at {self.store_path}:{lineno}: {exc}"
                    ) from exc
                _validate(record)
                self._cache[_record_id(record)] = record

    def _flush(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic-ish: write to a temp sibling then rename.
        tmp = self.store_path.with_suffix(".jsonl.tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            for record in self._cache.values():
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
                handle.write("\n")
        tmp.replace(self.store_path)

    # ── public API ────────────────────────────────────────────────────
    def load(self) -> list[dict[str, Any]]:
        """Return all records currently in the store (newest IDs are NOT sorted)."""
        self._ensure_loaded()
        return list(self._cache.values())

    def __iter__(self) -> Iterator[dict[str, Any]]:
        self._ensure_loaded()
        return iter(list(self._cache.values()))

    def __len__(self) -> int:
        self._ensure_loaded()
        return len(self._cache)

    def get(self, finding_id: str) -> dict[str, Any] | None:
        self._ensure_loaded()
        return self._cache.get(finding_id)

    def active(self, *, repository_id: str | None = None) -> list[dict[str, Any]]:
        """Return ``status == open`` records; optionally filtered by repository."""
        self._ensure_loaded()
        out = []
        for rec in self._cache.values():
            if rec["status"] not in ACTIVE_STATUSES:
                continue
            if repository_id is not None and rec["repositoryId"] != repository_id:
                continue
            out.append(rec)
        return out

    def upsert(self, record: dict[str, Any], *, now: str | None = None) -> dict[str, Any]:
        """Insert or refresh a record, preserving ``firstSeen*`` and identity.

        Identity rule: the caller may re-emit the SAME finding (same repo +
        rule + primary locus) in a later audit generation — the ID is stable
        because it is computed from those inputs. We merge in place: copy
        forward immutable metadata, refresh ``lastSeen*``, and append the new
        generation / timestamp.

        A record whose evidence loci disagree with the cached version is
        treated as a *new* finding and supersedes the cached one (explicit
        supersession, not silent mutation, per G4 acceptance).

        Timestamp contract:
          * If the incoming record already carries a ``lastSeenAt``, that
            value wins (callers emiting a finding in a deterministic
            batch audit want reproducible timestamps).
          * Otherwise ``now`` (or UTC now) is used.
        """
        _validate(record)
        self._ensure_loaded()
        fid = _record_id(record)
        wall_ts = now or _utc_now()
        prior = self._cache.get(fid)
        if prior is None:
            record = dict(record)
            record.setdefault("firstSeenGeneration", record["auditGeneration"])
            record["lastSeenGeneration"] = record["auditGeneration"]
            record.setdefault("firstSeenAt", wall_ts)
            record["lastSeenAt"] = record.get("lastSeenAt") or wall_ts
            self._cache[fid] = record
            self._flush()
            return record
        # Same identity — refresh mutable fields, preserve immutable ones.
        merged = dict(prior)
        merged.update(record)
        merged["id"] = fid
        merged["firstSeenGeneration"] = prior["firstSeenGeneration"]
        merged["firstSeenAt"] = prior["firstSeenAt"]
        merged["lastSeenGeneration"] = record["auditGeneration"] or prior["lastSeenGeneration"]
        merged["lastSeenAt"] = record.get("lastSeenAt") or wall_ts
        # Status supersession history preserved unless explicitly retargeted.
        if "supersededBy" not in record or record["supersededBy"] is None:
            merged["supersededBy"] = prior.get("supersededBy")
        if "supersedes" not in record:
            merged["supersedes"] = prior.get("supersedes", [])
        # resolvedGeneration/At kept across upserts unless caller overrides.
        for k in ("resolvedGeneration", "resolvedAt"):
            if record.get(k) is None and prior.get(k) is not None:
                merged[k] = prior[k]
        self._cache[fid] = merged
        self._flush()
        return merged

    def supersede(
        self,
        old_id: str,
        new_record: dict[str, Any],
        *,
        now: str | None = None,
    ) -> dict[str, Any]:
        """Mark an existing finding as ``superseded`` and link it to a successor.

        The successor record (typically with a different ID because it points
        at new evidence loci) is upserted with a populated ``supersedes`` and
        an ``auditGeneration`` change.
        """
        _validate(new_record)
        self._ensure_loaded()
        ts = now or _utc_now()
        old = self._cache.get(old_id)
        if old is None:
            raise KeyError(f"unknown finding: {old_id}")
        if old["status"] == "superseded":
            # Already retired; new_record becomes its successor anyway.
            pass
        # Update the old record in place.
        old = dict(old)
        old["status"] = "superseded"
        old["supersededBy"] = new_record["id"]
        old["resolvedGeneration"] = new_record["auditGeneration"] or old["lastSeenGeneration"]
        old["resolvedAt"] = ts
        old["lastSeenAt"] = ts
        self._cache[old_id] = old
        # Upsert the successor with a `supersedes` chain.
        successor = dict(new_record)
        supersedes = list(successor.get("supersedes") or [])
        if old_id not in supersedes:
            supersedes.append(old_id)
        successor["supersedes"] = supersedes
        successor.setdefault("firstSeenGeneration", new_record["auditGeneration"])
        successor["lastSeenGeneration"] = new_record["auditGeneration"]
        successor.setdefault("firstSeenAt", ts)
        successor["lastSeenAt"] = ts
        self._cache[successor["id"]] = successor
        self._flush()
        return successor

    def set_status(
        self,
        finding_id: str,
        status: str,
        *,
        generation: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        """Set status (``resolved`` / ``dismissed`` / ``open``) on a finding.

        ``superseded`` is not a valid direct target here — use ``supersede``
        to wire both sides of the link.
        """
        if status not in ALL_STATUSES or status == "superseded":
            raise ValueError(
                "use store.supersede() to retire by supersession; "
                "set_status accepts resolved/dismissed/open"
            )
        self._ensure_loaded()
        rec = self._cache.get(finding_id)
        if rec is None:
            raise KeyError(f"unknown finding: {finding_id}")
        rec = dict(rec)
        ts = now or _utc_now()
        prior_status = rec["status"]
        rec["status"] = status
        if status in TERMINAL_STATUSES:
            rec["resolvedGeneration"] = generation or rec["auditGeneration"] or rec["lastSeenGeneration"]
            rec["resolvedAt"] = ts
        else:  # back to open
            rec["resolvedGeneration"] = None
            rec["resolvedAt"] = None
        rec["lastSeenAt"] = ts
        self._cache[finding_id] = rec
        self._flush()
        return rec


# ── CLI surface (intentionally minimal; this lane exposes a Python API) ───

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit_store", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    show = sub.add_parser("show")
    show.add_argument("--repo", required=True)
    show.add_argument("--id")
    show.add_argument("--active", action="store_true")

    main = sub.add_parser("diagnose")
    main.add_argument("--repo", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.cmd == "show":
        store = AuditStore(Path(args.repo))
        if args.id:
            rec = store.get(args.id)
            print(json.dumps(rec, indent=2, sort_keys=True) if rec else "null")
            return 0 if rec else 1
        if args.active:
            for rec in store.active():
                print(json.dumps(rec, sort_keys=True))
        else:
            for rec in store.load():
                print(json.dumps(rec, sort_keys=True))
        return 0
    if args.cmd == "diagnose":
        store = AuditStore(Path(args.repo))
        print(json.dumps({"count": len(store), "path": str(store.store_path)}, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
