"""Matched blind/PeerDebate value-gate branch contracts."""
from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest


def _runner():
    try:
        return importlib.import_module("review.value_gate_runner")
    except ModuleNotFoundError:
        pytest.fail("review.value_gate_runner is not implemented")


def test_implementer_output_requires_exact_finding_coverage():
    findings = [
        {"finding_id": "f1", "claim": "one"},
        {"finding_id": "f2", "claim": "two"},
    ]
    valid = {
        "dispositions": [
            {
                "finding_id": "f1", "action": "folded",
                "rationale": "real", "revision_text": "Add a rollback check.",
            },
            {
                "finding_id": "f2", "action": "refuted",
                "rationale": "already measured", "revision_text": "",
            },
        ],
    }
    parsed = _runner().validate_implementer_output(valid, findings)
    assert {item["finding_id"] for item in parsed} == {"f1", "f2"}

    invalid = json.loads(json.dumps(valid))
    invalid["dispositions"].pop()
    with pytest.raises(ValueError, match="exactly once"):
        _runner().validate_implementer_output(invalid, findings)


def test_fold_requires_revision_and_refute_requires_rationale():
    findings = [{"finding_id": "f1", "claim": "one"}]
    with pytest.raises(ValueError, match="revision_text"):
        _runner().validate_implementer_output({
            "dispositions": [{
                "finding_id": "f1", "action": "folded",
                "rationale": "yes", "revision_text": "",
            }],
        }, findings)
    with pytest.raises(ValueError, match="rationale"):
        _runner().validate_implementer_output({
            "dispositions": [{
                "finding_id": "f1", "action": "refuted",
                "rationale": "", "revision_text": "",
            }],
        }, findings)


def test_revised_packet_addendum_stays_inside_artifact_section():
    packet = """```packet
ARTIFACT: Original plan.

SUCCESS_CRITERIA:
  - works

NON_GOALS:
  - none
```
"""
    revised = _runner().apply_folded_addendum(packet, [{
        "finding_id": "f1", "action": "folded",
        "rationale": "yes", "revision_text": "Add an observable rollback threshold.",
    }])
    assert revised.index("EXPERIMENTAL IMPLEMENTER REVISIONS") < revised.index("SUCCESS_CRITERIA:")
    assert "Add an observable rollback threshold." in revised


def test_blind_branch_strips_peer_material_and_preserves_input_identity(tmp_path: Path):
    peer = tmp_path / "peer"
    blind = tmp_path / "blind"
    peer.mkdir()
    packet = "```packet\nARTIFACT: x\n```\n"
    (peer / "packet.md").write_text(packet, encoding="utf-8")
    advisory = {
        "skill": "jury-plan",
        "jurors": [{"juror_id": "a", "blockers": []}],
        "accounting": {"calls": 1},
        "rebuttal": {"secret": "peer material"},
        "response": {"secret": "reply material"},
        "contest_audit": {"secret": "audit"},
    }
    (peer / "council.advisory.json").write_text(json.dumps(advisory), encoding="utf-8")
    (peer / "review.state.json").write_text(json.dumps({
        "skill": "jury-plan", "input_hash": "abc", "rebuttal": True,
    }), encoding="utf-8")

    _runner().prepare_blind_branch(peer, blind)

    copied = json.loads((blind / "council.advisory.json").read_text(encoding="utf-8"))
    state = json.loads((blind / "review.state.json").read_text(encoding="utf-8"))
    assert "rebuttal" not in copied and "response" not in copied
    assert state["input_hash"] == "abc"
    assert state["rebuttal"] is False
    assert state["dissent_policy"] == "none"
    assert (blind / "packet.md").read_text(encoding="utf-8") == packet
