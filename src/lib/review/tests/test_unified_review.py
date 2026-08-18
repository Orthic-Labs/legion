"""Contract tests for the one-skill Council -> revise -> Jury workflow."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dual_review  # noqa: E402
import review_evidence  # noqa: E402


def _panel_result(skill: str, concern: str) -> dict:
    return {
        "skill": skill,
        "packet_validation": {"ok": True, "errors": [], "warnings": []},
        "jurors": [{"juror_id": "seat", "blockers": [], "top_concern": concern}],
        "escalation": [],
        "synthesis": {"majority_verdict": "SHIP", "split": False},
    }


def test_full_review_revises_between_isolated_panels(monkeypatch, tmp_path: Path):
    calls: list[dict] = []

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            self.config = {
                "panels": {"advisory": {"jurors": [{"id": "helper"}]}},
                "skills": {"jury-plan": {"rubric": "rubrics/plan.md"}},
            }

        def run(self, *, skill, user_input, panel_name, jurors_override=None, **kwargs):
            calls.append({"panel": panel_name, "input": user_input})
            concern = "COUNCIL_SECRET_ADVICE" if panel_name == "council" else "jury concern"
            return _panel_result(skill, concern)

    monkeypatch.setattr(dual_review, "Engine", FakeEngine)
    monkeypatch.setattr(
        dual_review,
        "validate_packet",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, errors=[], warnings=[], sections={"ARTIFACT": "v1"}
        ),
    )

    def revise(original: str, advisory: dict):
        assert "COUNCIL_SECRET_ADVICE" in str(advisory)
        return original.replace("ARTIFACT: v1", "ARTIFACT: v2"), {
            "self_review": [],
            "advisory_dispositions": [
                {"finding": "COUNCIL_SECRET_ADVICE", "action": "accepted", "rationale": "useful"}
            ],
        }

    envelope = dual_review.run_dual_review(
        skill="jury-plan",
        input_text="```packet\nARTIFACT: v1\n```",
        out_dir=tmp_path,
        revise=revise,
    )

    assert [call["panel"] for call in calls] == ["council", "jury"]
    assert "ARTIFACT: v2" in calls[1]["input"]
    assert "COUNCIL_SECRET_ADVICE" not in calls[1]["input"]
    assert envelope["revision"]["changed"] is True
    assert (tmp_path / "council.advisory.json").is_file()
    assert (tmp_path / "jury.verdict.json").is_file()


def test_matching_advisory_checkpoint_is_resumed(monkeypatch, tmp_path: Path):
    calls = 0

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            self.config = {"panels": {"advisory": {"jurors": []}}}

        def run(self, **kwargs):
            nonlocal calls
            calls += 1
            return _panel_result(kwargs["skill"], "cached advice")

    monkeypatch.setattr(dual_review, "Engine", FakeEngine)
    monkeypatch.setattr(
        dual_review,
        "validate_packet",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, errors=[], warnings=[], sections={"ARTIFACT": "same"}
        ),
    )

    first = dual_review.run_advisory_review(
        skill="jury-plan", input_text="same packet", out_dir=tmp_path
    )
    second = dual_review.run_advisory_review(
        skill="jury-plan", input_text="same packet", out_dir=tmp_path
    )

    assert first == second
    assert calls == 1
    assert (tmp_path / "packet.md").read_text(encoding="utf-8") == "same packet"


def test_verdict_refuses_missing_advisory_before_calling_jury(monkeypatch, tmp_path: Path):
    calls = 0

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, **kwargs):
            nonlocal calls
            calls += 1
            return _panel_result(kwargs["skill"], "should not run")

    monkeypatch.setattr(dual_review, "Engine", FakeEngine)
    monkeypatch.setattr(
        dual_review,
        "validate_packet",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, errors=[], warnings=[], sections={"ARTIFACT": "v2"}
        ),
    )

    try:
        dual_review.run_verdict_review(
            skill="jury-plan",
            revised_input_text="revised",
            disposition={"self_review": [], "advisory_dispositions": []},
            out_dir=tmp_path,
        )
    except ValueError as error:
        assert "council.advisory.json" in str(error)
    else:
        raise AssertionError("missing advisory checkpoint did not fail")

    assert calls == 0


def test_peer_debate_run_is_pinned_under_canonical_runs_root(monkeypatch, tmp_path: Path):
    runs_root = tmp_path / ".council-runs"
    out_dir = runs_root / "real-loop2-1"

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            self.config = {"panels": {"advisory": {"jurors": []}}}

        def run(self, **kwargs):
            return _panel_result(kwargs["skill"], "blind")

    monkeypatch.setattr(dual_review, "Engine", FakeEngine)
    monkeypatch.setattr(
        dual_review,
        "validate_packet",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, errors=[], warnings=[], sections={"ARTIFACT": "v1"}
        ),
    )
    monkeypatch.setattr(
        dual_review,
        "run_rebuttal_round",
        lambda **kwargs: {"round": "PeerDebate", "jurors": [], "finding_index": {}},
    )
    monkeypatch.setattr(
        dual_review,
        "run_response_round",
        lambda **kwargs: {"round": "PeerDebateReply", "jurors": [], "routed_contests": {}},
    )

    dual_review.run_advisory_review(
        skill="jury-code",
        input_text="packet",
        out_dir=out_dir,
        rebuttal=True,
        runs_root=runs_root,
    )

    state = json.loads((out_dir / "review.state.json").read_text(encoding="utf-8"))
    assert state["lane"] == "p-1-peer-debate"
    assert state["evidence"]["run_id"] == "real-loop2-1"
    assert (out_dir / "evidence.manifest.json").is_file()


def test_room_verdict_refuses_open_finding_ledger_before_jury(monkeypatch, tmp_path: Path):
    calls = 0

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, **kwargs):
            nonlocal calls
            calls += 1
            return _panel_result(kwargs["skill"], "must not run")

    monkeypatch.setattr(dual_review, "Engine", FakeEngine)
    monkeypatch.setattr(
        dual_review,
        "validate_packet",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, errors=[], warnings=[], sections={"ARTIFACT": "v2"}
        ),
    )
    (tmp_path / "council.advisory.json").write_text("{}", encoding="utf-8")
    (tmp_path / "review.state.json").write_text(
        json.dumps({
            "schema_version": 1,
            "lane": "room",
            "finding_ledger": {"path": "finding-ledger.json", "sha256": "not-a-digest"},
            "open_finding_count": 1,
        }),
        encoding="utf-8",
    )
    (tmp_path / "finding-ledger.json").write_text(
        json.dumps({
            "schema_version": 1,
            "findings": [{"finding_id": "f1", "status": "Open"}],
            "dispositions": [],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="finding ledger"):
        dual_review.run_verdict_review(
            skill="jury-code",
            revised_input_text="revised",
            disposition={"self_review": [], "advisory_dispositions": []},
            out_dir=tmp_path,
        )
    assert calls == 0


def test_room_fallback_verdict_requires_completed_disposition_check(monkeypatch, tmp_path: Path):
    calls = 0

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, **kwargs):
            nonlocal calls
            calls += 1
            return _panel_result(kwargs["skill"], "must not run")

    monkeypatch.setattr(dual_review, "Engine", FakeEngine)
    monkeypatch.setattr(
        dual_review,
        "validate_packet",
        lambda *args, **kwargs: SimpleNamespace(
            ok=True, errors=[], warnings=[], sections={"ARTIFACT": "v2"}
        ),
    )
    (tmp_path / "council.advisory.json").write_text("{}", encoding="utf-8")
    (tmp_path / "review.state.json").write_text(
        json.dumps({
            "schema_version": 1,
            "lane": "room-fallback",
            "fallback": {"status": "disposition_check_required", "merge_forbidden": True},
        }),
        encoding="utf-8",
    )
    review_evidence.persist_finding_ledger(tmp_path, {
        "schema_version": 1,
        "findings": [{"finding_id": "f1", "status": "Folded"}],
        "dispositions": [{
            "disposition_id": "d1", "finding_id": "f1", "status": "Accepted",
            "receipt_refs": ["r1"],
        }],
        "receipts": [{"receipt_id": "r1", "kind": "artifact", "locator": "x.md:1"}],
    }, lane="room-fallback")

    with pytest.raises(ValueError, match="fallback disposition check"):
        dual_review.run_verdict_review(
            skill="jury-code",
            revised_input_text="revised",
            disposition={"self_review": [], "advisory_dispositions": []},
            out_dir=tmp_path,
        )
    assert calls == 0
