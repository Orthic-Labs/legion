"""Jury revision ledger — per-artifact blocker disposition log.

Arcane's completion controls consume this on-disk schema + CLI for each
artifact verdict round.

Per-artifact sidecar: `<artifact>.verdict.ledger.json` next to the
`<artifact>.verdict.json`. Travels with the artifact; greppable.

Schema (locked 2026-07-14):
{
  "schema_version": 1,
  "artifact": "out/shot3.mp4",
  "rounds": [
    {
      "round": 1,
      "ts": "2026-07-14T...",
      "verdict_path": "out/shot3.verdict.json",
      "blockers": [
        {"id": "b1", "tier": "P0", "text": "unhandled timeout in capture-loop",
         "from_juror": "code_specialist", "disposition": null}
      ]
    }
  ]
}

`disposition` ∈ {null, "fixed", "rebutted", "waived_by_operator"}.
`null` ≡ "pending".

CLI:
    python -m jury.ledger <artifact> \\
        --dispose b1=fixed:src/capture.rs:42 \\
        --dispose b2=rebutted:rubric.does_not_apply_to_videos \\
        --waive b3

  --dispose <id>=<disposition>[:<evidence>]
        evidence is a free-form string (file:line cite, code snippet, or note)

  --waive <id>      short for --dispose <id>=waived_by_operator

The CLI walks the ledger, finds the latest round, applies dispositions by
blocker id, and re-saves the ledger file. Adding NEW rounds is the
responsibility of the jury pipeline (auto-jury.mjs / runAutoJury); the
CLI never invents rounds.

Tier discipline: P0 blockers are critical (no count cap from the rubric).
All P0 blockers must be disposed before the artifact can ship. P1+P2 share
an 8-cap but every individual P1/P2 blocker still needs a disposition
— the cap is a *display* constraint, not a *disposition-skip* one.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union


VALID_DISPOSITIONS = {"fixed", "rebutted", "waived_by_operator"}
TIER_VALUES = {"P0", "P1", "P2"}

# Blocker id pattern: b<digits>. Id assignments are made when a verdict is
# registered; existing ids are preserved across CLI invocations.
_BLOCKER_ID_RE = re.compile(r"^b\d+$")


# ---------- Data model ----------

@dataclass
class BlockerEntry:
    id: str
    tier: str  # P0|P1|P2
    text: str
    from_juror: str = ""
    disposition: Optional[str] = None  # None = pending
    evidence: Optional[str] = None      # free-form cite / snippet / note
    disposed_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tier": self.tier,
            "text": self.text,
            "from_juror": self.from_juror,
            "disposition": self.disposition,
            "evidence": self.evidence,
            "disposed_at": self.disposed_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BlockerEntry":
        tier = (d.get("tier") or "P1").upper()
        if tier not in TIER_VALUES:
            tier = "P1"
        return cls(
            id=str(d.get("id", "")),
            tier=tier,
            text=str(d.get("text", "")).strip(),
            from_juror=str(d.get("from_juror", "")).strip(),
            disposition=d.get("disposition"),
            evidence=d.get("evidence"),
            disposed_at=d.get("disposed_at"),
        )


@dataclass
class Round:
    round: int
    ts: str
    verdict_path: str
    blockers: list[BlockerEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "round": self.round,
            "ts": self.ts,
            "verdict_path": self.verdict_path,
            "blockers": [b.to_dict() for b in self.blockers],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Round":
        return cls(
            round=int(d.get("round", 1)),
            ts=str(d.get("ts", "")),
            verdict_path=str(d.get("verdict_path", "")),
            blockers=[BlockerEntry.from_dict(b) for b in d.get("blockers") or []],
        )


@dataclass
class Ledger:
    schema_version: int
    artifact: str
    rounds: list[Round] = field(default_factory=list)

    def latest_round(self) -> Optional[Round]:
        return max(self.rounds, key=lambda r: r.round) if self.rounds else None

    def pending_blockers(self) -> list[BlockerEntry]:
        """Return pending blockers from the latest round only."""
        round_ = self.latest_round()
        if round_ is None:
            return []
        return [b for b in round_.blockers if b.disposition is None]

    def is_clean(self) -> bool:
        """True iff latest round has no pending blockers."""
        return not self.pending_blockers()

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "artifact": self.artifact,
            "rounds": [r.to_dict() for r in self.rounds],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Ledger":
        return cls(
            schema_version=int(d.get("schema_version", 1)),
            artifact=str(d.get("artifact", "")),
            rounds=[Round.from_dict(r) for r in d.get("rounds") or []],
        )


# ---------- File helpers ----------

def ledger_path_for(artifact: Union[str, Path]) -> Path:
    """`<basename>.verdict.ledger.json` next to `<basename>.verdict.json`."""
    p = Path(artifact)
    return p.parent / f"{p.stem}.verdict.ledger.json"


def load_ledger(path: Union[str, Path]) -> Optional[Ledger]:
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return Ledger.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except Exception:
        return None


def save_ledger(ledger: Ledger, path: Optional[Union[str, Path]] = None) -> Path:
    """Save the ledger JSON. Default path: next to the artifact."""
    if path is None:
        path = ledger_path_for(ledger.artifact)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(ledger.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return p


# ---------- Adding a new round from a verdict ----------

_TIER_FROM_BLOCKER = re.compile(r"\[(?P<tier>P0|P1|P2)\]")


def _normalize_blocker(b) -> tuple[str, str]:
    """Same normalizer the synthesizer uses."""
    if isinstance(b, dict):
        tier = (b.get("tier") or "P1").upper()
        if tier not in TIER_VALUES:
            tier = "P1"
        return tier, str(b.get("text", "")).strip()
    text = str(b).strip()
    m = _TIER_FROM_BLOCKER.match(text)
    if m:
        return m.group("tier"), _TIER_FROM_BLOCKER.sub("", text).strip()
    return "P1", text


def register_verdict_round(
    ledger: Ledger,
    *,
    verdict_path: Union[str, Path],
    juror_blockers: dict[str, list],
) -> Ledger:
    """Append a new round to the ledger from a verdict's per-juror blockers.

    `juror_blockers` is a dict of {juror_id: list_of_blockers}. Each
    blocker can be a str (legacy) or dict {tier, text} (new). The round
    number is the previous max + 1 (or 1 if empty). Existing blocker
    ids from earlier rounds are preserved; new blockers get fresh
    sequential ids.

    Existing blockers that already have a disposition from a prior round
    are NOT carried over — each round starts fresh. This is intentional:
    a round's blockers are those the verdict raised in this round;
    dispositions live in this round's record; if a blocker recurs in a
    later round, the prior disposition is preserved on the new id (look
    it up by text-match).
    """
    vp = Path(verdict_path)
    next_round = (max((r.round for r in ledger.rounds), default=0)) + 1
    ts = _dt.datetime.now(_dt.timezone.utc).isoformat()

    new_blockers: list[BlockerEntry] = []
    # Build a disposition lookup keyed by normalized text from prior
    # rounds so a recurring blocker keeps its disposition.
    prior_dispositions: dict[str, tuple[str, Optional[str]]] = {}
    for r in ledger.rounds:
        for b in r.blockers:
            if b.disposition:
                prior_dispositions[b.text.lower()] = (b.disposition, b.evidence)

    counter = 1
    # Stable ordering: juror alphabetical, blockers in list order
    for juror in sorted(juror_blockers.keys()):
        for blocker in juror_blockers[juror] or []:
            tier, text = _normalize_blocker(blocker)
            if not text:
                continue
            block_id = f"b{counter}"
            counter += 1
            # Inherit prior disposition if the text matches.
            prior = prior_dispositions.get(text.lower())
            new_blockers.append(BlockerEntry(
                id=block_id,
                tier=tier,
                text=text,
                from_juror=juror,
                disposition=prior[0] if prior else None,
                evidence=prior[1] if prior else None,
                disposed_at=_dt.datetime.now(_dt.timezone.utc).isoformat() if prior else None,
            ))

    round_ = Round(round=next_round, ts=ts, verdict_path=str(vp), blockers=new_blockers)
    ledger.rounds.append(round_)
    return ledger


# ---------- Disposing a blocker ----------

def dispose_blocker(
    ledger: Ledger,
    *,
    blocker_id: str,
    disposition: str,
    evidence: Optional[str] = None,
) -> bool:
    """Set the disposition on one blocker in the latest round.

    Returns True if a blocker was updated; False if the id wasn't found
    in the latest round (the caller should treat that as an error).
    """
    if disposition not in VALID_DISPOSITIONS:
        raise ValueError(f"invalid disposition: {disposition!r}; must be one of {sorted(VALID_DISPOSITIONS)}")
    if not _BLOCKER_ID_RE.match(blocker_id):
        raise ValueError(f"invalid blocker id: {blocker_id!r}; expected b<digits>")
    round_ = ledger.latest_round()
    if round_ is None:
        return False
    for b in round_.blockers:
        if b.id == blocker_id:
            b.disposition = disposition
            b.evidence = evidence
            b.disposed_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
            return True
    return False


# ---------- CLI ----------

def _parse_dispose_arg(arg: str) -> tuple[str, str, Optional[str]]:
    """Parse `b1=fixed:src/foo.rs:42` -> ("b1", "fixed", "src/foo.rs:42").

    Forms accepted:
      b1=fixed
      b1=fixed:some evidence cite
      b3=rebutted:rubric does not apply
    """
    if "=" not in arg:
        raise ValueError(f"--dispose expects id=disposition[:evidence], got {arg!r}")
    bid, rest = arg.split("=", 1)
    bid = bid.strip()
    if ":" in rest:
        disposition, evidence = rest.split(":", 1)
        return bid, disposition.strip(), evidence.strip()
    return bid, rest.strip(), None


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Jury revision ledger — dispose blockers, query state.")
    parser.add_argument("artifact", help="artifact path (used to locate the ledger sidecar)")
    parser.add_argument("--dispose", action="append", default=[], help="b1=disposition[:evidence] (repeatable)")
    parser.add_argument("--waive", action="append", default=[], help="blocker id to waive by the operator (repeatable)")
    parser.add_argument("--status", action="store_true", help="print ledger summary and exit")
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    args = parser.parse_args(argv)

    lp = ledger_path_for(args.artifact)
    ledger = load_ledger(lp) or Ledger(schema_version=1, artifact=str(args.artifact))

    if not args.dispose and not args.waive and not args.status:
        # Default: print status
        args.status = True

    if args.dispose or args.waive:
        # Apply disposes first (idempotent)
        any_applied = False
        for arg in args.dispose:
            bid, disp, ev = _parse_dispose_arg(arg)
            ok = dispose_blocker(ledger, blocker_id=bid, disposition=disp, evidence=ev)
            if not ok:
                print(f"warning: blocker id {bid!r} not found in latest round", file=sys.stderr)
            else:
                any_applied = True
        for bid in args.waive:
            ok = dispose_blocker(ledger, blocker_id=bid, disposition="waived_by_operator")
            if not ok:
                print(f"warning: blocker id {bid!r} not found in latest round", file=sys.stderr)
            else:
                any_applied = True
        if any_applied:
            save_ledger(ledger, lp)
            print(f"ledger saved: {lp}")

    if args.status or args.json:
        pending = ledger.pending_blockers()
        payload = {
            "ledger_path": str(lp),
            "artifact": ledger.artifact,
            "rounds": len(ledger.rounds),
            "latest_round": ledger.latest_round().round if ledger.latest_round() else None,
            "pending_count": len(pending),
            "is_clean": ledger.is_clean(),
            "pending_blockers": [b.to_dict() for b in pending],
        }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"ledger:   {lp}")
            print(f"rounds:   {payload['rounds']}")
            print(f"latest:   {payload['latest_round']}")
            print(f"pending:  {payload['pending_count']}")
            print(f"clean:    {payload['is_clean']}")
            for b in pending:
                print(f"  - [{b.tier}] {b.id} (from {b.from_juror}): {b.text}")

    return 0 if ledger.is_clean() else 1


if __name__ == "__main__":
    sys.exit(main())
