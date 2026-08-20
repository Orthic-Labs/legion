"""Architect decision store — durable JSONL backing for ArchitectDecisionV1.

Architect-owned decision store. Persists typed decision records to a per-repository
JSONL store at `.audit/architect/decisions.jsonl`. Owns the stable-ID
derivation so that the same logical decision gets the same id across
re-saves, worktrees, and machines (modulo repository identity).

This module is intentionally narrow: read, append, get-by-id, list-active.
Lifecycle enforcement (proposed -> accepted -> implemented -> superseded)
and candidate emission live in `decision_provider.py`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA_VERSION = 1
STORE_RELATIVE_PATH = Path(".audit") / "architect" / "decisions.jsonl"

# Status values are constrained to the v1 schema enum. Re-declared here as
# a frozen tuple so external modules can import them without re-parsing the
# JSON schema.
STATUSES: tuple[str, ...] = (
    "proposed",
    "accepted",
    "implemented",
    "superseded",
)

# Identifier helpers — kept in one place so the same scheme is used by the
# store, provider, tests, and any future tooling.
DECISION_ID_PREFIX = "architect:decision"


def _canonical(value: str) -> str:
    """Canonicalize a string for hashing (strip + lower)."""

    return (value or "").strip().lower()


def derive_decision_id(
    *,
    repository_id: str,
    task_id: str,
    linked_graph_generation: str,
    rationale: str,
) -> str:
    """Derive the stable, content-addressed decision id.

    Two records are considered the SAME decision when their repository, task,
    graph generation, and rationale are all equal. The id is a 24-char
    sha256-prefix of that canonical key so it is reproducible, collision-
    resistant for realistic workloads, and short enough for human eyeballing.
    """

    key = "|".join(
        (
            _canonical(repository_id),
            _canonical(task_id),
            _canonical(linked_graph_generation),
            _canonical(rationale),
        )
    )
    digest = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()
    return f"{DECISION_ID_PREFIX}:{digest[:24]}"


def _ensure_status(value: Any, *, field: str = "currentStatus") -> str:
    if value not in STATUSES:
        raise ValueError(f"{field}={value!r} not in {STATUSES}")
    return value


@dataclass(frozen=True)
class DecisionRecord:
    """An immutable view over a single JSONL row."""

    record: dict[str, Any]
    line_number: int

    @property
    def id(self) -> str:
        return str(self.record["id"])

    @property
    def current_status(self) -> str:
        return str(self.record["currentStatus"])


def _default_store_path(repo_root: Path | str) -> Path:
    return Path(repo_root) / STORE_RELATIVE_PATH


class DecisionStore:
    """Append-only JSONL store of ArchitectDecisionV1 records.

    All writes are atomic-append (write-temp, fsync, rename) so the file
    never contains a half-written line, even on crash. Reads are streaming
    and tolerant of malformed lines (they are skipped with the read yielding
    only well-formed records) — this protects long-running consumers from a
    single corrupted historical write.
    """

    def __init__(self, store_path: Path | str | None = None) -> None:
        self._path = Path(store_path) if store_path is not None else None

    @property
    def path(self) -> Path:
        if self._path is None:
            raise RuntimeError("DecisionStore has no path configured")
        return self._path

    # ---- construction helpers -------------------------------------------------

    @classmethod
    def for_repo(cls, repo_root: Path | str) -> "DecisionStore":
        return cls(_default_store_path(repo_root))

    # ---- read API -------------------------------------------------------------

    def __iter__(self) -> Iterator[DecisionRecord]:
        return self.iter_records()

    def iter_records(self) -> Iterator[DecisionRecord]:
        if not self.path.exists():
            return iter(())
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue
                if record.get("schemaVersion") != SCHEMA_VERSION:
                    continue
                yield DecisionRecord(record=record, line_number=line_number)

    def get(self, decision_id: str) -> DecisionRecord | None:
        for entry in self.iter_records():
            if entry.id == decision_id:
                return entry
        return None

    def list_active(self, *, repository_id: str | None = None) -> list[DecisionRecord]:
        """Return the set of decisions whose current status is NOT 'superseded'.

        When `repository_id` is supplied the result is additionally filtered
        to records whose repositoryId matches. Order is stable: file order,
        which equals insertion order for the append-only store.
        """

        active: list[DecisionRecord] = []
        for entry in self.iter_records():
            if entry.current_status == "superseded":
                continue
            if repository_id is not None and entry.record.get("repositoryId") != repository_id:
                continue
            active.append(entry)
        return active

    # ---- write API ------------------------------------------------------------

    def append(self, record: dict[str, Any]) -> DecisionRecord:
        """Append a single decision record. Returns the persisted record.

        The record is validated lightly (id + status must be present) but full
        JSON-schema validation is the responsibility of the caller; the store
        is a persistence layer, not a contract enforcer. Writes go through a
        temp-file-then-rename so the JSONL never contains a half-written line.
        """

        if not isinstance(record, dict):
            raise TypeError("record must be a dict")
        if "id" not in record or not record["id"]:
            raise ValueError("record is missing non-empty 'id'")
        _ensure_status(record.get("currentStatus"), field="currentStatus")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, sort_keys=True) + "\n"
        # Crash-safe append: copy the existing file (if any), append the new
        # line, then atomic-rename over the target. We deliberately do NOT
        # open the target in 'a' mode because Windows 'a' is not crash-safe
        # for JSONL (a power-cut mid-write can leave a partial line at EOF).
        existing = self.path.read_bytes() if self.path.exists() else b""
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("wb") as handle:
            handle.write(existing)
            handle.write(line.encode("utf-8"))
            handle.flush()
        tmp.replace(self.path)
        return DecisionRecord(record=dict(record), line_number=-1)

    def replace_all(self, records: Iterable[dict[str, Any]]) -> list[DecisionRecord]:
        """Rewrite the entire store with the given records (test helper)."""

        new_records = [dict(record) for record in records]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            for record in new_records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
        # Atomic rename over the existing file.
        tmp.replace(self.path)
        return [
            DecisionRecord(record=dict(record), line_number=index + 1)
            for index, record in enumerate(new_records)
        ]
