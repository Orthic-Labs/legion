"""Production Council Room driver contracts."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agent_room_driver  # noqa: E402
import dual_review  # noqa: E402
import review_evidence  # noqa: E402


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def _passed_gate(root: Path) -> None:
    gate = root / "value-gate-final-test"
    gate.mkdir(parents=True)
    _write_json(gate / "value-gate.result.json", {
        "schema_version": 1,
        "passed": True,
        "denominator": 3,
        "material_change_count": 2,
    })
    _write_json(gate / "review.state.json", {"schema_version": 1, "status": "complete"})
    review_evidence.pin_run_evidence(gate, runs_root=root)


def _terminal_ledger() -> dict:
    return {
        "schema_version": 1,
        "room_id": "council-review-test",
        "findings": [{"finding_id": "finding-1", "status": "Refuted", "claim": "claim"}],
        "dispositions": [{
            "disposition_id": "disposition-1",
            "finding_id": "finding-1",
            "action": "refuted",
            "status": "Accepted",
            "final_receipt_refs": ["receipt-1"],
        }],
        "receipts": [{
            "receipt_id": "receipt-1",
            "kind": "file",
            "locator": "packet.md:1",
        }],
    }


def test_council_skill_routes_every_advisory_stage_through_room() -> None:
    skill_path = Path(__file__).resolve().parents[2] / "skills" / "council" / "SKILL.md"
    contract = skill_path.read_text(encoding="utf-8")

    assert "Loop 1, Loop 2, and single-loop reviews" in contract
    assert "--stage advisory --room" in contract
    assert "Loop 1 and every single-loop review stay isolated" not in contract
    assert "--ack-room-link-delivered" in contract
    assert "send the returned `user_notification.message` to the operator immediately" in contract


def test_room_driver_launches_then_resumes_from_terminal_export(tmp_path: Path) -> None:
    runs_root = tmp_path / ".council-runs"
    runs_root.mkdir()
    _passed_gate(runs_root)
    output = runs_root / "review-test"
    binary = tmp_path / "room.exe"
    binary.write_bytes(b"test-binary")
    calls: list[list[str]] = []

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess:
        calls.append(command)
        run_dir = Path(command[command.index("--run-dir") + 1])
        run_dir.mkdir(parents=True, exist_ok=True)
        if command[1] == "spawn":
            _write_json(run_dir / "runtime.json", {
                "room_id": "council-review-test",
                "base_url": "http://127.0.0.1:43119",
                "pairing_code": "pair-code",
            })
            _write_json(run_dir / "seat-readiness.json", {
                "schema_version": 1,
                "status": "ready",
                "seats": [
                    {"name": "Claude", "seat_id": "seat-claude", "status": "ready", "ready_event_seq": 2},
                    {"name": "Codex", "seat_id": "seat-codex", "status": "ready", "ready_event_seq": 3},
                    {"name": "MiniMax", "seat_id": "seat-minimax", "status": "ready", "ready_event_seq": 4},
                ],
            })
        elif command[1] == "export":
            _write_json(run_dir / "finding-ledger.json", _terminal_ledger())
            (run_dir / "transcript.jsonl").write_text('{"seq":1}\n', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    active = agent_room_driver.run_room_advisory(
        skill="jury-plan",
        input_text="packet",
        out_dir=output,
        runs_root=runs_root,
        workspace_root=tmp_path,
        room_binary=binary,
        runner=runner,
        acknowledge_link_delivery=True,
    )
    assert active["status"] == "room_active"
    assert "--scope-ref" in calls[0]
    assert calls[0][calls[0].index("--seats") + 1] == "claude,codex,minimax"
    assert "--no-open" in calls[0]
    assert "--readiness-timeout-secs" in calls[0]
    assert active["watch_url"] == "http://127.0.0.1:43119/join/pair-code"
    assert active["user_notification"] == {
        "required": True,
        "status": "pending",
        "message": "Council Room is live: http://127.0.0.1:43119/join/pair-code",
        "next_action": "send_to_user_then_acknowledge",
    }
    active_state = json.loads((output / "review.state.json").read_text(encoding="utf-8"))
    assert active_state["room"]["watch_url"] == active["watch_url"]
    assert "pairing_code" not in active_state["room"]
    assert active_state["room"]["link_delivery"]["status"] == "pending"

    still_pending = agent_room_driver.run_room_advisory(
        skill="jury-plan",
        input_text="packet",
        out_dir=output,
        runs_root=runs_root,
        workspace_root=tmp_path,
        room_binary=binary,
        runner=runner,
    )
    assert still_pending["status"] == "room_active"
    assert still_pending["user_notification"]["status"] == "pending"
    assert [command[1] for command in calls] == ["spawn"]

    complete = agent_room_driver.run_room_advisory(
        skill="jury-plan",
        input_text="packet",
        out_dir=output,
        runs_root=runs_root,
        workspace_root=tmp_path,
        room_binary=binary,
        runner=runner,
        acknowledge_link_delivery=True,
    )
    assert complete["status"] == "complete"
    assert complete["findings"][0]["finding_id"] == "finding-1"
    state = json.loads((output / "review.state.json").read_text(encoding="utf-8"))
    assert state["lane"] == "room"
    assert state["status"] == "awaiting_revision"
    assert state["open_finding_count"] == 0
    assert state["room"]["link_delivery"]["status"] == "acknowledged"
    assert state["room"]["link_delivery"]["acknowledged_at"]
    assert review_evidence.verify_run_evidence(output, runs_root=runs_root)["ok"] is True


def test_room_active_cli_output_is_the_mandatory_user_notice() -> None:
    result = {
        "status": "room_active",
        "user_notification": {
            "required": True,
            "status": "pending",
            "message": "Council Room is live: http://127.0.0.1:43119/join/pair-code",
            "next_action": "send_to_user_then_acknowledge",
        },
    }

    rendered = dual_review.render_cli_result(result)

    assert rendered.startswith("MANDATORY USER NOTIFICATION\n")
    assert "Council Room is live: http://127.0.0.1:43119/join/pair-code" in rendered
    assert "--ack-room-link-delivered" in rendered


def test_acknowledged_room_active_cli_output_remains_renderable() -> None:
    result = {
        "status": "room_active",
        "watch_url": "http://127.0.0.1:43119/join/pair-code",
        "user_notification": {
            "required": False,
            "status": "acknowledged",
            "message": "Council Room is live: http://127.0.0.1:43119/join/pair-code",
            "next_action": "wait_for_room_completion",
        },
    }

    rendered = dual_review.render_cli_result(result)

    assert rendered == "Council Room link delivered. Room remains active.\n"


def test_dual_review_forwards_room_link_delivery_acknowledgement(
    monkeypatch, tmp_path: Path
) -> None:
    observed: dict = {}

    def fake_room_advisory(**kwargs: object) -> dict:
        observed.update(kwargs)
        return {"status": "room_active"}

    monkeypatch.setattr(dual_review, "_validate_input", lambda *_args: None)
    monkeypatch.setattr(dual_review, "run_room_advisory", fake_room_advisory)

    dual_review.run_advisory_review(
        skill="jury-plan",
        input_text="packet",
        out_dir=tmp_path,
        runs_root=tmp_path,
        room=True,
        acknowledge_room_link_delivery=True,
    )

    assert observed["acknowledge_link_delivery"] is True


def test_room_driver_refuses_missing_value_gate(tmp_path: Path) -> None:
    root = tmp_path / ".council-runs"
    root.mkdir()
    binary = tmp_path / "room.exe"
    binary.write_bytes(b"test")
    try:
        agent_room_driver.run_room_advisory(
            skill="jury-plan",
            input_text="packet",
            out_dir=root / "review",
            runs_root=root,
            workspace_root=tmp_path,
            room_binary=binary,
        )
    except ValueError as error:
        assert "value gate" in str(error)
    else:
        raise AssertionError("missing gate must fail closed")


def test_room_driver_refuses_success_without_durable_seat_readiness(tmp_path: Path) -> None:
    runs_root = tmp_path / ".council-runs"
    runs_root.mkdir()
    _passed_gate(runs_root)
    output = runs_root / "review-test"
    binary = tmp_path / "room.exe"
    binary.write_bytes(b"test-binary")

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess:
        run_dir = Path(command[command.index("--run-dir") + 1])
        run_dir.mkdir(parents=True, exist_ok=True)
        _write_json(run_dir / "runtime.json", {
            "room_id": "council-review-test",
            "base_url": "http://127.0.0.1:43119",
            "pairing_code": "pair-code",
        })
        return subprocess.CompletedProcess(command, 0, "", "")

    result = agent_room_driver.run_room_advisory(
        skill="jury-plan",
        input_text="packet",
        out_dir=output,
        runs_root=runs_root,
        workspace_root=tmp_path,
        room_binary=binary,
        runner=runner,
    )

    assert result["status"] == "fallback_required"
    state = json.loads((output / "review.state.json").read_text(encoding="utf-8"))
    assert state["lane"] == "room-fallback"
    assert state["fallback"]["partial_room_sealed"] is True


def test_room_driver_aborts_ready_room_when_runtime_record_is_missing(tmp_path: Path) -> None:
    runs_root = tmp_path / ".council-runs"
    runs_root.mkdir()
    _passed_gate(runs_root)
    output = runs_root / "review-test"
    binary = tmp_path / "room.exe"
    binary.write_bytes(b"test-binary")
    calls: list[list[str]] = []

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess:
        calls.append(command)
        run_dir = Path(command[command.index("--run-dir") + 1])
        run_dir.mkdir(parents=True, exist_ok=True)
        if command[1] == "spawn":
            _write_json(run_dir / "seat-readiness.json", {
                "schema_version": 1,
                "status": "ready",
                "seats": [
                    {"seat_id": "seat-claude", "status": "ready", "ready_event_seq": 2},
                    {"seat_id": "seat-codex", "status": "ready", "ready_event_seq": 3},
                    {"seat_id": "seat-minimax", "status": "ready", "ready_event_seq": 4},
                ],
            })
        return subprocess.CompletedProcess(command, 0, "", "")

    result = agent_room_driver.run_room_advisory(
        skill="jury-plan",
        input_text="packet",
        out_dir=output,
        runs_root=runs_root,
        workspace_root=tmp_path,
        room_binary=binary,
        runner=runner,
    )

    assert result["status"] == "fallback_required"
    assert [command[1] for command in calls] == ["spawn", "abort"]


def test_room_driver_never_persists_raw_launcher_stderr(tmp_path: Path) -> None:
    runs_root = tmp_path / ".council-runs"
    runs_root.mkdir()
    _passed_gate(runs_root)
    output = runs_root / "review-test"
    binary = tmp_path / "room.exe"
    binary.write_bytes(b"test-binary")

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess:
        run_dir = Path(command[command.index("--run-dir") + 1])
        run_dir.mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(command, 1, "", "secret-token-must-not-persist")

    result = agent_room_driver.run_room_advisory(
        skill="jury-plan",
        input_text="packet",
        out_dir=output,
        runs_root=runs_root,
        workspace_root=tmp_path,
        room_binary=binary,
        runner=runner,
    )

    assert result["status"] == "fallback_required"
    partial = (output / "room" / "partial-room.json").read_text(encoding="utf-8")
    assert "secret-token-must-not-persist" not in partial


def test_room_driver_preserves_failed_launch_diagnostics_and_enters_fallback(tmp_path: Path) -> None:
    runs_root = tmp_path / ".council-runs"
    runs_root.mkdir()
    _passed_gate(runs_root)
    output = runs_root / "review-test"
    binary = tmp_path / "room.exe"
    binary.write_bytes(b"test-binary")

    def runner(command: list[str], **_: object) -> subprocess.CompletedProcess:
        run_dir = Path(command[command.index("--run-dir") + 1])
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "room.sqlite3").write_bytes(b"partial-sqlite")
        (run_dir / "seat-claude.stderr.log").write_text("Not logged in\n", encoding="utf-8")
        _write_json(run_dir / "launch.failure.json", {
            "schema_version": 1,
            "status": "aborted",
            "stage": "preflight",
            "seat_failures": [{
                "seat": "claude",
                "code": "authentication_failed",
                "detail": "Claude CLI is not authenticated; run /login.",
                "stderr_log": "seat-claude.stderr.log",
            }],
        })
        return subprocess.CompletedProcess(command, 1, "", "room launch failed")

    result = agent_room_driver.run_room_advisory(
        skill="jury-plan",
        input_text="packet",
        out_dir=output,
        runs_root=runs_root,
        workspace_root=tmp_path,
        room_binary=binary,
        runner=runner,
    )

    assert result["status"] == "fallback_required"
    assert result["seat_failures"][0]["code"] == "authentication_failed"
    assert (output / "room" / "room.sqlite3").read_bytes() == b"partial-sqlite"
    assert (output / "room" / "seat-claude.stderr.log").is_file()
    state = json.loads((output / "review.state.json").read_text(encoding="utf-8"))
    assert state["lane"] == "room-fallback"
    partial = output / state["fallback"]["partial_ledger"]["path"]
    assert partial.is_file()
