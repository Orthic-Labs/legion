"""Tests for the rebuttal/response rounds and the debate viewer.

Focus is audit integrity: every check here exists because a defect made a
non-compliant round render as clean. No network — pure functions over fixtures.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from review.dual_review import (  # noqa: E402
    _contest_audit,
    _contests_by_target,
    _peer_positions_block,
    _resolution_audit,
    _strip_unsupported_adoptions,
    run_rebuttal_round,
    run_response_round,
)
from review.render_debate import render  # noqa: E402


def seat(seat_id, *, blockers=None, parsed=True, error=None, **extra):
    juror = {
        "juror_id": seat_id, "parsed_ok": parsed, "verdict": "REVISE",
        "score": 70, "top_concern": f"{seat_id} concern",
        "blockers": blockers if blockers is not None else [],
    }
    if error:
        juror["error"] = error
    juror.update(extra)
    return juror


def contest(finding_id: str, *, text: str = "overstated") -> dict:
    return {
        "tier": "P1",
        "text": text,
        "contest": {
            "finding_id": finding_id,
            "rationale": text,
            "evidence_refs": [],
        },
    }


def resolution(finding_id: str, choice: str, *, evidence_refs=None) -> dict:
    return {
        "tier": "P1",
        "text": f"{choice}: answer",
        "resolution": {
            "finding_id": finding_id,
            "choice": choice,
            "reason": "answer",
            "evidence_refs": evidence_refs or [],
        },
    }


# --- contest audit: partial compliance is not compliance ---------------------

@pytest.mark.parametrize("contesting,total,expect_herding", [
    (0, 3, True),    # nobody contested
    (1, 3, True),    # 2 of 3 herded — the defect Codex found
    (2, 3, True),    # 1 herded
    (3, 3, False),   # full compliance
])
def test_herding_fires_on_any_shortfall(contesting, total, expect_herding):
    jurors = [
        seat(f"s{i}", blockers=[contest(f"finding-{(i+1)%total}") if i < contesting else "own finding"])
        for i in range(total)
    ]
    audit = _contest_audit({"jurors": jurors})
    assert audit["contesting_seats"] == contesting
    assert audit["herding_suspected"] is expect_herding
    assert audit["fully_compliant"] is (contesting == total)


def test_failed_seat_is_counted_not_hidden():
    audit = _contest_audit({"jurors": [
        seat("a", blockers=[contest("finding-b")]),
        seat("b", blockers=[contest("finding-a")]),
        seat("c", parsed=False, error="timeout after 120s"),
    ]})
    assert audit["failed_seats"] == ["c"]
    assert audit["answering_seats"] == 2
    assert audit["total_seats"] == 3
    # Both answering seats contested, but a dead seat means the round is not clean.
    assert audit["herding_suspected"] is False
    assert audit["fully_compliant"] is False


# --- adoption stripping: the charter's promise, enforced ---------------------

def test_unsupported_adoption_is_discarded():
    advisory = {"jurors": [seat("a", blockers=["The orchestrator judges its own refutations"])]}
    rebuttal = {"jurors": [seat("b", blockers=[
        "CONTEST: a — overstated",
        "The orchestrator judges its own refutations",
    ])]}
    out = _strip_unsupported_adoptions(rebuttal, advisory)
    kept = out["jurors"][0]["blockers"]
    assert kept == ["CONTEST: a — overstated"]
    assert out["jurors"][0]["discarded_adoptions"] == [
        "The orchestrator judges its own refutations"
    ]


def test_supported_adoption_survives():
    advisory = {"jurors": [seat("a", blockers=["The orchestrator judges its own refutations"])]}
    rebuttal = {"jurors": [seat("b", blockers=[
        "CONTEST: a — overstated",
        "The orchestrator judges its own refutations — I missed that step 5 has no second reader",
    ])]}
    out = _strip_unsupported_adoptions(rebuttal, advisory)
    assert len(out["jurors"][0]["blockers"]) == 2
    assert "discarded_adoptions" not in out["jurors"][0]


def test_own_finding_not_mistaken_for_adoption():
    advisory = {"jurors": [seat("a", blockers=["Peer finding about caching"])]}
    rebuttal = {"jurors": [seat("b", blockers=["CONTEST: a — no", "A totally separate concern"])]}
    out = _strip_unsupported_adoptions(rebuttal, advisory)
    assert len(out["jurors"][0]["blockers"]) == 2


# --- peer positions: full evidence, failures visible ------------------------

def test_peer_block_carries_all_rubric_fields_and_hides_raw():
    advisory = {"jurors": [
        seat("a", blockers=["b1"], strengths=["s1"], raw="MODEL SCAFFOLDING LEAK"),
    ]}
    block = _peer_positions_block(advisory, exclude_id="z")
    assert "b1" in block
    assert "finding_id" in block
    assert "strengths" not in block and "s1" not in block
    assert "verdict" not in block and "score" not in block
    assert "SCAFFOLDING" not in block


def test_peer_block_does_not_leak_failed_seat_plumbing():
    advisory = {"jurors": [seat("a", parsed=False, error="429 rate limited")]}
    block = _peer_positions_block(advisory, exclude_id="z")
    assert "429" not in block and "error" not in block


# --- contest routing + resolution -------------------------------------------

def test_contests_route_to_named_target():
    routed = _contests_by_target({
        "finding_index": {
            "finding-skeptic": {"author_seat": "council:skeptic"},
            "finding-reasoner": {"author_seat": "council:reasoner"},
        },
        "jurors": [
            seat("council:reasoner", blockers=[contest("finding-skeptic")]),
            seat("council:skeptic", blockers=[contest("finding-reasoner", text="too soft")]),
        ],
    })
    assert set(routed) == {"council:skeptic", "council:reasoner"}
    assert routed["council:skeptic"][0]["from"] == "council:reasoner"


@pytest.mark.parametrize("blocker,expected", [
    (resolution("finding-a", "concede"), "conceded"),
    (resolution("finding-a", "sustain", evidence_refs=["dual_review.py:138"]), "sustained"),
    (resolution("finding-a", "sustain"), "unanswered"),
])
def test_resolution_outcomes(blocker, expected):
    audit = _resolution_audit({"jurors": [seat("b", blockers=[blocker])]})
    assert audit["resolutions"][0]["outcome"] == expected
    assert audit["all_contests_resolved"] is (expected != "unanswered")


def test_unanswered_contest_blocks_seal():
    audit = _resolution_audit({"jurors": [
        seat("b", blockers=[resolution("finding-a", "concede")]),
        seat("c", parsed=False, error="timeout"),
    ]})
    assert audit["open_contests"] == 1
    assert audit["all_contests_resolved"] is False


def test_resolution_must_target_each_routed_finding_exactly_once():
    audit = _resolution_audit({
        "routed_contests": {
            "b": [
                {"from": "a", "finding_id": "finding-1"},
                {"from": "c", "finding_id": "finding-2"},
            ],
        },
        "jurors": [seat("b", blockers=[resolution("finding-1", "concede")])],
    })
    assert audit["conceded_count"] == 1
    assert audit["open_contests"] == 1
    assert audit["all_contests_resolved"] is False


def test_peer_debate_dissent_policy_is_explicit_not_post_hoc():
    prompts = []

    class FakeEngine:
        config = {
            "panels": {
                "advisory": {
                    "jurors": [
                        {"id": "a"},
                        {"id": "b"},
                    ],
                },
            },
        }

        def run(self, **kwargs):
            prompts.append(kwargs["user_input"])
            assert kwargs["no_cache"] is True
            seat_id = kwargs["jurors_override"][0]["id"]
            return {
                "jurors": [seat(seat_id, blockers=[])],
                "accounting": {
                    "calls": 1,
                    "usage": {
                        "input_tokens": 10,
                        "output_tokens": 5,
                        "total_tokens": 15,
                    },
                    "usage_complete": True,
                },
            }

    advisory = {"jurors": [seat("a", blockers=["a finding"]), seat("b", blockers=["b finding"])]}
    run_rebuttal_round(
        skill="jury-code", input_text="packet", advisory=advisory,
        engine=FakeEngine(), dissent_policy="none",
    )
    assert prompts and all("MANDATORY" not in prompt for prompt in prompts)

    prompts.clear()
    result = run_rebuttal_round(
        skill="jury-code", input_text="packet", advisory=advisory,
        engine=FakeEngine(), dissent_policy="required_contest",
    )
    assert prompts and all("MANDATORY" in prompt for prompt in prompts)
    assert result["dissent_policy"] == "required_contest"
    assert result["accounting"] == {
        "calls": 2,
        "usage": {"input_tokens": 20, "output_tokens": 10, "total_tokens": 30},
        "usage_complete": True,
    }


def test_response_round_answers_all_contests_with_one_bounded_rewake():
    calls = []

    class FakeEngine:
        config = {
            "panels": {"advisory": {"jurors": [{"id": "author"}]}},
        }

        def run(self, **kwargs):
            calls.append(kwargs)
            finding_id = "finding-1" if len(calls) == 1 else "finding-2"
            return {
                "jurors": [seat(
                    "author",
                    blockers=[resolution(finding_id, "concede")],
                )],
                "accounting": {
                    "calls": 1,
                    "usage": {
                        "input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
                    },
                    "usage_complete": True,
                },
            }

    response = run_response_round(
        skill="jury-plan",
        input_text="packet",
        advisory={"jurors": [seat("author")]},
        rebuttal={
            "finding_index": {
                "finding-1": {"author_seat": "author"},
                "finding-2": {"author_seat": "author"},
            },
            "jurors": [
                seat("peer-a", blockers=[contest("finding-1")]),
                seat("peer-b", blockers=[contest("finding-2")]),
            ],
        },
        engine=FakeEngine(),
    )

    audit = _resolution_audit(response)
    assert len(calls) == 2
    assert all(call["no_cache"] is True for call in calls)
    assert response["jurors"][0]["rewake_count"] == 1
    assert audit["conceded_count"] == 2
    assert audit["open_contests"] == 0
    assert response["accounting"]["calls"] == 2


# --- viewer -----------------------------------------------------------------

def _write(tmp_path: Path, payload: dict) -> Path:
    (tmp_path / "council.advisory.json").write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


def test_viewer_flags_partial_compliance_and_shows_failed_seat(tmp_path):
    out = render(_write(tmp_path, {
        "skill": "jury-plan",
        "jurors": [seat("a", blockers=["x"]), seat("b", blockers=["y"]), seat("c", blockers=["z"])],
        "rebuttal": {"jurors": [
            seat("a", blockers=[contest("finding-b")]),
            seat("b", blockers=["agreed with everything"]),
            seat("c", parsed=False, error="timeout after 120s"),
        ]},
    }))
    assert "Failed seats" in out and "timeout after 120s" in out
    assert "silent, not agreeing" in out
    assert 'class="metric flag"' in out          # partial compliance flagged
    assert "1 / 2" in out                        # contested / answering


def test_viewer_renders_response_round_as_replies(tmp_path):
    out = render(_write(tmp_path, {
        "skill": "jury-plan",
        "jurors": [seat("a", blockers=["x"]), seat("b", blockers=["y"])],
        "rebuttal": {"jurors": [
            seat("a", blockers=[contest("finding-b")]),
            seat("b", blockers=[contest("finding-a", text="too soft")]),
        ]},
        "response": {"jurors": [
            seat("b", blockers=[resolution("finding-b", "concede")], answering_contests=["a"]),
        ]},
        "resolution_audit": {"conceded_count": 1, "sustained_count": 0, "open_contests": 0},
    }))
    assert "Round 3" in out
    assert "PeerDebate" in out
    assert "rebuttals" not in out
    assert 'class="msg reply"' in out
    assert "answering a" in out
    assert 'class="b concede"' in out


def test_viewer_marks_discarded_adoptions(tmp_path):
    out = render(_write(tmp_path, {
        "skill": "jury-plan",
        "jurors": [seat("a", blockers=["x"])],
        "rebuttal": {"jurors": [
            seat("a", blockers=[contest("finding-b")], discarded_adoptions=["copied peer finding"]),
        ]},
    }))
    assert 'class="b discarded"' in out
    assert "unsupported adoption" in out


def test_viewer_recomputes_audit_for_legacy_runs(tmp_path):
    """A run predating contest_audit must not render as compliant."""
    out = render(_write(tmp_path, {
        "skill": "jury-plan",
        "jurors": [seat("a", blockers=["x"]), seat("b", blockers=["y"])],
        "rebuttal": {"jurors": [
            seat("a", blockers=["adopted everything"]),
            seat("b", blockers=["adopted everything too"]),
        ]},
    }))
    assert 'class="metric flag"' in out
    assert "0 / 2" in out
