"""Evidence pinning, scheduled obligations, and frozen value-gate tests."""
from __future__ import annotations

import importlib
import hashlib
import json
from pathlib import Path

import pytest


def _evidence():
    try:
        return importlib.import_module("review.review_evidence")
    except ModuleNotFoundError:
        pytest.fail("review.review_evidence is not implemented")


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def _run_dir(runs_root: Path, run_id: str, sample: dict | None = None) -> Path:
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True)
    _write_json(run_dir / "review.state.json", {"schema_version": 1, "status": "complete"})
    _write_json(run_dir / "council.advisory.json", {"jurors": [{"juror_id": "a"}]})
    if sample is not None:
        _write_json(run_dir / "value-gate.sample.json", sample)
    return run_dir


def _sample(run_id: str, *, material: bool = False, inflated: bool = False) -> dict:
    blind_disposition = {"f1": "folded"}
    debate_disposition = {"f1": "refuted"} if material else dict(blind_disposition)
    return {
        "schema_version": 1,
        "run_id": run_id,
        "review_kind": "jury-code",
        "self_referential": False,
        "loop": 2,
        "real_review": True,
        "blind": {
            "dispositions": blind_disposition,
            "jury_verdict_tier": "REVISE",
            "blockers": ["b1"],
        },
        "peer_debate": {
            "dispositions": debate_disposition,
            "jury_verdict_tier": "REVISE",
            "blockers": ["b1", "b2"] if inflated else ["b1"],
        },
        "room": {
            "escalation_rate": 0.25,
            "calls": 6,
            "tokens": 1200,
            "usage_source": "provider",
            "usage_complete": True,
        },
        "operator_adjudication": {
            "adjudicated_by": "the operator",
            "correct_minority_erased": False,
            "notes": "checked against pinned artifacts",
        },
    }


def test_pin_manifest_updates_state_and_detects_artifact_drift(tmp_path):
    runs_root = tmp_path / ".council-runs"
    run_dir = _run_dir(runs_root, "run-a")
    manifest = _evidence().pin_run_evidence(run_dir, runs_root=runs_root)
    state = json.loads((run_dir / "review.state.json").read_text(encoding="utf-8"))

    assert manifest["run_id"] == "run-a"
    assert state["evidence"]["run_id"] == "run-a"
    assert state["evidence"]["artifacts"][0]["sha256"]
    assert _evidence().verify_run_evidence(run_dir, runs_root=runs_root)["ok"] is True

    (run_dir / "council.advisory.json").write_text("{}", encoding="utf-8")
    verification = _evidence().verify_run_evidence(run_dir, runs_root=runs_root)
    assert verification["ok"] is False
    assert verification["mismatches"][0]["path"] == "council.advisory.json"


def test_pin_rejects_run_outside_canonical_root(tmp_path):
    runs_root = tmp_path / ".council-runs"
    outside = _run_dir(tmp_path / "elsewhere", "run-a")
    with pytest.raises(ValueError, match="canonical runs root"):
        _evidence().pin_run_evidence(outside, runs_root=runs_root)


def test_scheduled_findings_survive_restart_reenter_and_escalate_if_phase_disappears(tmp_path):
    state_path = tmp_path / "review.state.json"
    _write_json(state_path, {"schema_version": 1, "status": "awaiting_revision"})
    _evidence().schedule_finding(
        state_path,
        finding_id="finding-1",
        source_phase="Task 1",
        owner_phase="Task 2",
        claim="Needs runtime proof",
        missing_evidence="measurement",
        source_ledger_digest="a" * 64,
    )

    # Reload from disk to prove restart survival.
    reentered = _evidence().reconcile_scheduled_findings(
        state_path, current_phase="Task 2", phase_order=["Task 1", "Task 2", "Task 3"],
    )
    assert reentered["scheduled_findings"][0]["status"] == "Open"
    with pytest.raises(ValueError, match="open finding cannot be rescheduled"):
        _evidence().schedule_finding(
            state_path,
            finding_id="finding-1",
            source_phase="Task 2",
            owner_phase="Task 3",
            claim="escape", missing_evidence="none", source_ledger_digest="b" * 64,
        )

    state_path_2 = tmp_path / "missing-phase.state.json"
    _write_json(state_path_2, {"schema_version": 1})
    _evidence().schedule_finding(
        state_path_2,
        finding_id="finding-2",
        source_phase="Task 1",
        owner_phase="Removed Task",
        claim="Orphan", missing_evidence="proof", source_ledger_digest="c" * 64,
    )
    escalated = _evidence().reconcile_scheduled_findings(
        state_path_2, current_phase="Task 2", phase_order=["Task 1", "Task 2"],
    )
    assert escalated["scheduled_findings"][0]["status"] == "Escalated"


def test_frozen_value_gate_passes_only_three_distinct_pinned_real_loop2_samples(tmp_path):
    runs_root = tmp_path / ".council-runs"
    run_dirs = []
    for index in range(3):
        run_id = f"real-loop2-{index + 1}"
        sample = _sample(run_id, material=index == 0)
        if index == 1:
            sample["review_kind"] = "jury-plan"  # allowed when it is not this room plan
        run_dir = _run_dir(runs_root, run_id, sample)
        _evidence().pin_run_evidence(run_dir, runs_root=runs_root)
        run_dirs.append(run_dir)

    result = _evidence().evaluate_frozen_value_gate(run_dirs, runs_root=runs_root)
    assert result["denominator"] == 3
    assert result["material_change_count"] == 1
    assert result["passed"] is True
    assert result["definition"] == _evidence().FROZEN_VALUE_GATE


def test_frozen_value_gate_rejects_inflation_and_self_referential_packets(tmp_path):
    runs_root = tmp_path / ".council-runs"
    run_dirs = []
    for index in range(3):
        run_id = f"real-loop2-{index + 1}"
        sample = _sample(run_id, material=index == 0, inflated=index == 1)
        run_dir = _run_dir(runs_root, run_id, sample)
        _evidence().pin_run_evidence(run_dir, runs_root=runs_root)
        run_dirs.append(run_dir)
    result = _evidence().evaluate_frozen_value_gate(run_dirs, runs_root=runs_root)
    assert result["passed"] is False
    assert "blocker_inflation" in result["failures"]

    bad = json.loads((run_dirs[2] / "value-gate.sample.json").read_text(encoding="utf-8"))
    bad["review_kind"] = "jury-plan"
    bad["self_referential"] = True
    _write_json(run_dirs[2] / "value-gate.sample.json", bad)
    _evidence().pin_run_evidence(run_dirs[2], runs_root=runs_root)
    with pytest.raises(ValueError, match="self-referential jury-plan"):
        _evidence().evaluate_frozen_value_gate(run_dirs, runs_root=runs_root)


def test_frozen_value_gate_requires_operator_adjudication_and_exact_denominator(tmp_path):
    runs_root = tmp_path / ".council-runs"
    run_dirs = []
    for index in range(3):
        run_id = f"real-loop2-{index + 1}"
        sample = _sample(run_id, material=index == 0)
        if index == 2:
            sample.pop("operator_adjudication")
        run_dir = _run_dir(runs_root, run_id, sample)
        _evidence().pin_run_evidence(run_dir, runs_root=runs_root)
        run_dirs.append(run_dir)

    with pytest.raises(ValueError, match="the operator adjudication"):
        _evidence().evaluate_frozen_value_gate(run_dirs, runs_root=runs_root)
    with pytest.raises(ValueError, match="exactly 3"):
        _evidence().evaluate_frozen_value_gate(run_dirs[:2], runs_root=runs_root)


def test_frozen_value_gate_requires_call_and_token_accounting(tmp_path):
    runs_root = tmp_path / ".council-runs"
    run_dirs = []
    for index in range(3):
        run_id = f"real-loop2-{index + 1}"
        sample = _sample(run_id, material=index == 0)
        if index == 2:
            sample["room"].pop("tokens")
        run_dir = _run_dir(runs_root, run_id, sample)
        _evidence().pin_run_evidence(run_dir, runs_root=runs_root)
        run_dirs.append(run_dir)
    with pytest.raises(ValueError, match="calls/tokens"):
        _evidence().evaluate_frozen_value_gate(run_dirs, runs_root=runs_root)


def test_frozen_value_gate_rejects_incomplete_or_untrusted_usage(tmp_path):
    runs_root = tmp_path / ".council-runs"
    run_dirs = []
    for index in range(3):
        run_id = f"real-loop2-{index + 1}"
        sample = _sample(run_id, material=index == 0)
        if index == 2:
            sample["room"]["usage_complete"] = False
            sample["room"]["usage_source"] = "estimated"
        run_dir = _run_dir(runs_root, run_id, sample)
        _evidence().pin_run_evidence(run_dir, runs_root=runs_root)
        run_dirs.append(run_dir)
    with pytest.raises(ValueError, match="complete provider or CLI self-report"):
        _evidence().evaluate_frozen_value_gate(run_dirs, runs_root=runs_root)


def test_build_value_gate_sample_copies_and_pins_both_branches(tmp_path):
    source_root = tmp_path / "sources"
    blind = source_root / "blind"
    debate = source_root / "debate"
    blind.mkdir(parents=True)
    debate.mkdir(parents=True)

    def write_branch(
        path: Path, *, action: str, verdict: str, blocker: str, rebuttal: bool,
    ):
        (path / "packet.md").write_text("same real review packet\n", encoding="utf-8")
        _write_json(path / "review.state.json", {
            "schema_version": 1,
            "skill": "jury-code",
            "input_hash": "same-input-hash",
            "rebuttal": rebuttal,
            "dissent_policy": "required_contest" if rebuttal else "none",
            "peer_phase": "PeerDebate" if rebuttal else None,
        })
        _write_json(path / "review.disposition.json", {
            "self_review": [],
            "advisory_dispositions": [{
                "finding_id": "finding-1", "action": action,
            }],
        })
        _write_json(path / "jury.verdict.json", {
            "synthesis": {"majority_verdict": verdict},
            "jurors": [{"parsed_ok": True, "blockers": [blocker]}],
            "accounting": {
                "calls": 4,
                "usage": {"input_tokens": 60, "output_tokens": 40, "total_tokens": 100},
                "usage_complete": True,
            },
        })
        _write_json(path / "council.advisory.json", {
            "accounting": {
                "calls": 3,
                "usage": {"input_tokens": 30, "output_tokens": 20, "total_tokens": 50},
                "usage_complete": True,
            },
        })

    write_branch(
        blind, action="folded", verdict="REVISE", blocker="b1", rebuttal=False,
    )
    write_branch(
        debate, action="refuted", verdict="SHIP", blocker="b2", rebuttal=True,
    )
    _write_json(debate / "council.rebuttal.json", {
        "accounting": {
            "calls": 3,
            "usage": {"input_tokens": 24, "output_tokens": 16, "total_tokens": 40},
            "usage_complete": True,
        },
    })
    _write_json(debate / "council.response.json", {
        "accounting": {
            "calls": 3,
            "usage": {"input_tokens": 18, "output_tokens": 12, "total_tokens": 30},
            "usage_complete": True,
        },
        "resolution_audit": {
            "resolutions": [
                {"outcome": "sustained"}, {"outcome": "sustained"},
                {"outcome": "sustained"}, {"outcome": "sustained"},
                {"outcome": "sustained"}, {"outcome": "unanswered"},
            ],
            "unanswered_count": 1,
        },
    })

    runs_root = tmp_path / ".council-runs"
    result = _evidence().build_value_gate_sample(
        run_id="real-loop2-1",
        blind_run_dir=blind,
        peer_debate_run_dir=debate,
        review_kind="jury-code",
        self_referential=False,
        operator_adjudication={
            "adjudicated_by": "the operator",
            "correct_minority_erased": False,
            "notes": "checked",
        },
        runs_root=runs_root,
    )

    run_dir = runs_root / "real-loop2-1"
    assert result["blind"]["dispositions"] == {"finding-1": "folded"}
    assert result["peer_debate"]["dispositions"] == {"finding-1": "refuted"}
    assert result["peer_debate"]["jury_verdict_tier"] == "SHIP"
    assert result["room"] == {
        "escalation_count": 1,
        "escalation_eligible": 6,
        "escalation_rate": pytest.approx(1 / 6),
        "calls": 6,
        "tokens": 70,
        "usage_source": "provider",
        "usage_complete": True,
    }
    assert (run_dir / "blind" / "jury.verdict.json").is_file()
    assert (run_dir / "blind" / "packet.md").is_file()
    assert (run_dir / "peer_debate" / "council.response.json").is_file()
    manifest = json.loads((run_dir / "evidence.manifest.json").read_text(encoding="utf-8"))
    assert "peer_debate/review.state.json" in {
        artifact["path"] for artifact in manifest["artifacts"]
    }
    assert _evidence().verify_run_evidence(run_dir, runs_root=runs_root)["ok"] is True


def test_build_value_gate_sample_rejects_unmatched_branch_packet(tmp_path):
    # Reuse a complete generated pair, then prove packet identity is load-bearing.
    blind = tmp_path / "blind"
    debate = tmp_path / "debate"
    for path, rebuttal, packet in (
        (blind, False, "packet-a"), (debate, True, "packet-b"),
    ):
        path.mkdir()
        (path / "packet.md").write_text(packet, encoding="utf-8")
        _write_json(path / "review.state.json", {
            "skill": "jury-code", "input_hash": "different" if rebuttal else "same",
            "rebuttal": rebuttal,
            "dissent_policy": "required_contest" if rebuttal else "none",
            "peer_phase": "PeerDebate" if rebuttal else None,
        })
        _write_json(path / "review.disposition.json", {
            "advisory_dispositions": [{"finding_id": "f1", "action": "folded"}],
        })
        _write_json(path / "jury.verdict.json", {
            "synthesis": {"majority_verdict": "REVISE"}, "jurors": [],
        })
    _write_json(debate / "council.advisory.json", {})
    _write_json(debate / "council.rebuttal.json", {})
    _write_json(debate / "council.response.json", {})

    with pytest.raises(ValueError, match="same pinned input packet"):
        _evidence().build_value_gate_sample(
            run_id="invalid-pair",
            blind_run_dir=blind,
            peer_debate_run_dir=debate,
            review_kind="jury-code",
            self_referential=False,
            operator_adjudication={
                "adjudicated_by": "the operator", "correct_minority_erased": False,
            },
            runs_root=tmp_path / ".council-runs",
        )


def test_terminal_ledger_gate_rejects_unknown_receipts_and_accepts_structural_receipts(tmp_path):
    ledger = {
        "schema_version": 1,
        "findings": [{"finding_id": "f1", "status": "Folded"}],
        "dispositions": [{
            "disposition_id": "d1",
            "finding_id": "f1",
            "status": "Accepted",
            "receipt_refs": ["receipt-1"],
        }],
        "receipts": [],
    }
    _evidence().persist_finding_ledger(tmp_path, ledger)
    with pytest.raises(ValueError, match="unknown receipt"):
        _evidence().verify_terminal_finding_ledger(tmp_path)

    ledger["receipts"] = [{
        "receipt_id": "receipt-1",
        "kind": "artifact",
        "locator": "artifact.md:1",
    }]
    _evidence().persist_finding_ledger(tmp_path, ledger)
    verified = _evidence().verify_terminal_finding_ledger(tmp_path)
    assert verified["findings"][0]["status"] == "Folded"


def test_verified_room_memory_archives_once_with_provenance(tmp_path):
    ledger = {
        "schema_version": 1,
        "findings": [{"finding_id": "f1", "status": "Refuted", "claim": "Measured claim"}],
        "dispositions": [{
            "disposition_id": "d1",
            "finding_id": "f1",
            "status": "Accepted",
            "receipt_refs": ["receipt-1"],
        }],
        "receipts": [{"receipt_id": "receipt-1", "kind": "file", "locator": "proof.md:1"}],
    }
    (tmp_path / "room").mkdir()
    (tmp_path / "room" / "transcript.jsonl").write_text('{"seq":1}\n', encoding="utf-8")
    _evidence().persist_finding_ledger(
        tmp_path,
        ledger,
        transcript_path="room/transcript.jsonl",
    )
    _write_json(tmp_path / "jury.verdict.json", {
        "synthesis": {"majority_verdict": "SHIP"},
    })
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    first = _evidence().archive_verified_room_memory(
        tmp_path,
        scope="D--Claude",
        crypt="crypt-test",
        runner=runner,
    )
    second = _evidence().archive_verified_room_memory(
        tmp_path,
        scope="D--Claude",
        crypt="crypt-test",
        runner=runner,
    )
    assert first == second
    assert first["status"] == "stored"
    assert len(calls) == 1
    assert calls[0][0][1] == "put"
    assert calls[0][0][calls[0][0].index("--artifact-family") + 1] == "skill_output"
    assert calls[0][0][calls[0][0].index("--producer") + 1] == "agent_room"
    assert calls[0][0][calls[0][0].index("--record-type") + 1] == "review_verdict"
    memory = (tmp_path / "room-memory.md").read_text(encoding="utf-8")
    assert "verified_terminal_ledger: true" in memory
    assert "Jury verdict: SHIP" in memory


def test_evidence_cli_pins_and_verifies_a_run(tmp_path, capsys):
    runs_root = tmp_path / ".council-runs"
    run_dir = _run_dir(runs_root, "cli-run")
    assert _evidence().main([
        "pin", str(run_dir), "--runs-root", str(runs_root),
    ]) == 0
    pin_output = json.loads(capsys.readouterr().out)
    assert pin_output["run_id"] == "cli-run"

    assert _evidence().main([
        "verify", str(run_dir), "--runs-root", str(runs_root),
    ]) == 0
    verify_output = json.loads(capsys.readouterr().out)
    assert verify_output["ok"] is True


def test_room_fallback_seals_partial_and_requires_two_isolated_passes(tmp_path):
    state_path = tmp_path / "review.state.json"
    _write_json(state_path, {"schema_version": 1, "lane": "room"})
    packet = tmp_path / "packet.md"
    packet.write_text("pinned packet\n", encoding="utf-8")
    partial = tmp_path / "partial-ledger.json"
    partial.write_text("{}\n", encoding="utf-8")
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

    state = _evidence().start_room_fallback(
        state_path,
        pinned_packet_path="packet.md",
        pinned_packet_digest=digest(packet),
        partial_ledger_path="partial-ledger.json",
        partial_ledger_digest=digest(partial),
    )
    assert state["lane"] == "room-fallback"
    assert state["fallback"]["status"] == "finding_pass_required"
    assert state["fallback"]["partial_room_sealed"] is True
    assert state["fallback"]["merge_forbidden"] is True

    findings = tmp_path / "fallback-findings.json"
    findings.write_text("{}\n", encoding="utf-8")
    state = _evidence().advance_room_fallback(
        state_path,
        completed_pass="finding",
        artifact_path="fallback-findings.json",
        artifact_digest=digest(findings),
    )
    assert state["fallback"]["status"] == "disposition_check_required"

    dispositions = tmp_path / "fallback-dispositions.json"
    dispositions.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="author acceptance"):
        _evidence().advance_room_fallback(
            state_path,
            completed_pass="disposition_check",
            artifact_path="fallback-dispositions.json",
            artifact_digest=digest(dispositions),
            author_acceptance_complete=False,
        )
    state = _evidence().advance_room_fallback(
        state_path,
        completed_pass="disposition_check",
        artifact_path="fallback-dispositions.json",
        artifact_digest=digest(dispositions),
        author_acceptance_complete=True,
    )
    assert state["fallback"]["status"] == "ready_for_verdict"
