"""Tests for review.ledger — per-artifact blocker disposition log."""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from review.ledger import (  # noqa: E402
    Ledger,
    Round,
    BlockerEntry,
    VALID_DISPOSITIONS,
    TIER_VALUES,
    dispose_blocker,
    ledger_path_for,
    load_ledger,
    register_verdict_round,
    save_ledger,
    _parse_dispose_arg,
)


# ---------- Helpers ----------

def _make_ledger(tmp: Path, *, artifact: str = "out/shot3.mp4") -> Ledger:
    return Ledger(schema_version=1, artifact=artifact)


def _round_with_blockers(blockers: list[tuple[str, str, str]], round_n: int = 1) -> Round:
    """blockers = [(tier, juror, text), ...]"""
    entries = []
    for i, (tier, juror, text) in enumerate(blockers, start=1):
        entries.append(BlockerEntry(id=f"b{i}", tier=tier, text=text, from_juror=juror))
    return Round(
        round=round_n,
        ts="2026-07-14T00:00:00Z",
        verdict_path=f"out/shot3.verdict.json",
        blockers=entries,
    )


# ---------- Tests ----------

def test_ledger_path_for(tmp: Path) -> None:
    p = ledger_path_for("out/shot3.mp4")
    assert p.name == "shot3.verdict.ledger.json"
    assert p.parent.name == "out"


def test_register_round_creates_blockers(tmp: Path) -> None:
    led = _make_ledger(tmp)
    register_verdict_round(
        led,
        verdict_path="out/shot3.verdict.json",
        juror_blockers={
            "code_specialist": [
                {"tier": "P0", "text": "unhandled timeout in capture loop"},
                "legacy bare string",
                "[P2] legacy with prefix",
            ],
            "fast_code": [{"tier": "P1", "text": "rename to match stdlib"}],
        },
    )
    assert len(led.rounds) == 1
    r = led.rounds[0]
    assert len(r.blockers) == 4
    # tier normalization
    tiers = [b.tier for b in r.blockers]
    assert tiers == ["P0", "P1", "P2", "P1"]
    # ids are sequential
    ids = [b.id for b in r.blockers]
    assert ids == ["b1", "b2", "b3", "b4"]
    # jurors preserved
    jurors = sorted({b.from_juror for b in r.blockers})
    assert jurors == ["code_specialist", "fast_code"]


def test_register_round_advances_number(tmp: Path) -> None:
    led = _make_ledger(tmp)
    register_verdict_round(
        led,
        verdict_path="out/shot3.verdict.json",
        juror_blockers={"a": [{"tier": "P1", "text": "first"}]},
    )
    register_verdict_round(
        led,
        verdict_path="out/shot3.verdict.json",
        juror_blockers={"a": [{"tier": "P1", "text": "second"}]},
    )
    assert [r.round for r in led.rounds] == [1, 2]


def test_dispose_blocker_sets_status() -> None:
    led = _make_ledger(Path("."))
    led.rounds.append(_round_with_blockers([("P0", "code_specialist", "ship-blocker")]))
    ok = dispose_blocker(led, blocker_id="b1", disposition="fixed", evidence="src/x.rs:42")
    assert ok is True
    assert led.is_clean() is True
    b = led.latest_round().blockers[0]
    assert b.disposition == "fixed"
    assert b.evidence == "src/x.rs:42"
    assert b.disposed_at is not None


def test_dispose_blocker_unknown_id_returns_false() -> None:
    led = _make_ledger(Path("."))
    led.rounds.append(_round_with_blockers([("P1", "a", "x")]))
    ok = dispose_blocker(led, blocker_id="b999", disposition="fixed")
    assert ok is False


def test_dispose_blocker_invalid_disposition_raises() -> None:
    led = _make_ledger(Path("."))
    led.rounds.append(_round_with_blockers([("P1", "a", "x")]))
    try:
        dispose_blocker(led, blocker_id="b1", disposition="nope")
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_dispose_blocker_invalid_id_format_raises() -> None:
    led = _make_ledger(Path("."))
    led.rounds.append(_round_with_blockers([("P1", "a", "x")]))
    try:
        dispose_blocker(led, blocker_id="X1", disposition="fixed")
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_waive_shortcut() -> None:
    led = _make_ledger(Path("."))
    led.rounds.append(_round_with_blockers([("P2", "a", "nice-to-have")]))
    ok = dispose_blocker(led, blocker_id="b1", disposition="waived_by_operator")
    assert ok is True
    assert led.is_clean()


def test_recurring_blocker_inherits_disposition(tmp: Path) -> None:
    led = _make_ledger(tmp)
    # Round 1: blocker "timeout", dispose as fixed
    register_verdict_round(
        led,
        verdict_path="out/x.verdict.json",
        juror_blockers={"a": [{"tier": "P0", "text": "timeout in capture"}]},
    )
    dispose_blocker(led, blocker_id="b1", disposition="fixed", evidence="src/x.rs:10")
    # Round 2: same blocker appears again
    register_verdict_round(
        led,
        verdict_path="out/x.verdict.json",
        juror_blockers={"a": [{"tier": "P0", "text": "timeout in capture"}]},
    )
    latest = led.latest_round()
    assert latest.blockers[0].disposition == "fixed"
    assert latest.blockers[0].evidence == "src/x.rs:10"
    assert led.is_clean()


def test_save_load_round_trip(tmp: Path) -> None:
    led = _make_ledger(tmp)
    led.rounds.append(_round_with_blockers([("P0", "a", "x"), ("P1", "b", "y")]))
    dispose_blocker(led, blocker_id="b1", disposition="fixed")
    p = save_ledger(led, tmp / "x.verdict.ledger.json")
    loaded = load_ledger(p)
    assert loaded is not None
    assert loaded.artifact == led.artifact
    assert loaded.rounds[0].blockers[0].disposition == "fixed"
    assert loaded.rounds[0].blockers[1].disposition is None  # pending


def test_pending_blockers_only_from_latest_round(tmp: Path) -> None:
    led = _make_ledger(tmp)
    led.rounds.append(_round_with_blockers([("P1", "a", "x")], round_n=1))
    dispose_blocker(led, blocker_id="b1", disposition="fixed")
    led.rounds.append(_round_with_blockers([("P1", "b", "y")], round_n=2))
    pending = led.pending_blockers()
    assert len(pending) == 1
    assert pending[0].text == "y"
    assert pending[0].from_juror == "b"


def test_pending_count_keeps_p0_unbounded() -> None:
    """P0 has no count cap, but every P0 still needs a disposition."""
    led = _make_ledger(Path("."))
    blockers = [("P0", f"juror{i}", f"ship-blocker {i}") for i in range(15)]
    led.rounds.append(_round_with_blockers(blockers))
    pending = led.pending_blockers()
    assert len(pending) == 15  # all 15 P0s need disposition
    # dispose half
    for i in range(1, 9):
        dispose_blocker(led, blocker_id=f"b{i}", disposition="fixed")
    pending = led.pending_blockers()
    assert len(pending) == 7


def test_parse_dispose_arg_three_forms() -> None:
    assert _parse_dispose_arg("b1=fixed") == ("b1", "fixed", None)
    assert _parse_dispose_arg("b2=fixed:src/foo.rs:42") == ("b2", "fixed", "src/foo.rs:42")
    assert _parse_dispose_arg("b3=rebutted:rubric does not apply") == ("b3", "rebutted", "rubric does not apply")


def test_parse_dispose_arg_rejects_malformed() -> None:
    try:
        _parse_dispose_arg("b1")
        assert False, "should have raised"
    except ValueError:
        pass


def test_valid_dispositions_locked() -> None:
    assert VALID_DISPOSITIONS == {"fixed", "rebutted", "waived_by_operator"}


def test_tier_values_locked() -> None:
    assert TIER_VALUES == {"P0", "P1", "P2"}


# ---------- Runner ----------

if __name__ == "__main__":
    import tempfile

    tests_need_tmp = {
        test_ledger_path_for,
        test_register_round_creates_blockers,
        test_register_round_advances_number,
        test_recurring_blocker_inherits_disposition,
        test_save_load_round_trip,
        test_pending_blockers_only_from_latest_round,
    }
    tests = [
        test_ledger_path_for,
        test_register_round_creates_blockers,
        test_register_round_advances_number,
        test_dispose_blocker_sets_status,
        test_dispose_blocker_unknown_id_returns_false,
        test_dispose_blocker_invalid_disposition_raises,
        test_dispose_blocker_invalid_id_format_raises,
        test_waive_shortcut,
        test_recurring_blocker_inherits_disposition,
        test_save_load_round_trip,
        test_pending_blockers_only_from_latest_round,
        test_pending_count_keeps_p0_unbounded,
        test_parse_dispose_arg_three_forms,
        test_parse_dispose_arg_rejects_malformed,
        test_valid_dispositions_locked,
        test_tier_values_locked,
    ]
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        for t in tests:
            try:
                if t in tests_need_tmp:
                    t(tmp)
                else:
                    t()
            except Exception as e:
                failures.append(f"{t.__name__}: {e}")
    if failures:
        print(f"FAIL ({len(failures)}/{len(tests)}):")
        for f in failures:
            print(f"  {f}")
        sys.exit(1)
    else:
        print(f"PASS {len(tests)}/{len(tests)}")