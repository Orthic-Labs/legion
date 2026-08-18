"""Resumable production driver for phase-gated Council Room reviews."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from review_evidence import (
    RUNS_ROOT,
    persist_finding_ledger,
    pin_run_evidence,
    start_room_fallback,
    verify_run_evidence,
    verify_terminal_finding_ledger,
)


Runner = Callable[..., subprocess.CompletedProcess]
ROOM_SEATS = ("claude", "codex", "minimax")
READINESS_TIMEOUT_SECS = 60


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_passed_value_gate(runs_root: str | Path = RUNS_ROOT) -> dict:
    root = Path(runs_root).resolve()
    candidates = sorted(root.glob("value-gate-final-*/value-gate.result.json"), reverse=True)
    for result_path in candidates:
        result = _read_json(result_path)
        verification = verify_run_evidence(result_path.parent, runs_root=root)
        if result.get("passed") is True and verification.get("ok") is True:
            return {
                "path": str(result_path),
                "sha256": _sha256(result_path),
                "denominator": result.get("denominator"),
                "material_change_count": result.get("material_change_count"),
            }
    raise ValueError("Agent Room frozen value gate is missing, failed, or digest-invalid")


def resolve_room_binary(explicit: str | Path | None = None) -> Path:
    candidates = [
        Path(explicit) if explicit else None,
        Path(os.environ["AGENT_ROOM_BIN"]) if os.environ.get("AGENT_ROOM_BIN") else None,
        Path(shutil.which("room") or "") if shutil.which("room") else None,
        Path(__file__).resolve().parents[1] / "rightkit" / "target" / "debug" / "room.exe",
        Path(__file__).resolve().parents[1] / "rightkit" / "target" / "debug" / "room",
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return candidate.resolve()
    raise ValueError("Agent Room CLI binary is unavailable; build agent-room-core first")


def _room_id(out_dir: Path) -> str:
    safe = "".join(character.lower() if character.isalnum() else "-" for character in out_dir.name)
    return f"council-{safe.strip('-')}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pending_link_delivery(watch_url: str) -> dict:
    return {
        "required": True,
        "status": "pending",
        "created_at": _now_iso(),
        "watch_url_sha256": hashlib.sha256(watch_url.encode("utf-8")).hexdigest(),
    }


def _active_result(state: dict) -> dict:
    delivery = state["room"].get("link_delivery") or {}
    pending = delivery.get("status") != "acknowledged"
    notification = {
        "required": pending,
        "status": "pending" if pending else "acknowledged",
        "message": f'Council Room is live: {state["room"]["watch_url"]}',
        "next_action": (
            "send_to_user_then_acknowledge" if pending else "wait_for_room_completion"
        ),
    }
    return {
        "schema_version": 1,
        "panel": "council",
        "lane": "room",
        "status": "room_active",
        "watch_url": state["room"]["watch_url"],
        "user_notification": notification,
        "room": state["room"],
        "jurors": [],
        "synthesis": {"majority_verdict": "PENDING_ROOM"},
    }


def _fallback_result(state: dict, diagnostic: dict) -> dict:
    return {
        "schema_version": 1,
        "panel": "council",
        "lane": "room-fallback",
        "status": "fallback_required",
        "room": state.get("room") or {},
        "fallback": state["fallback"],
        "seat_failures": diagnostic.get("seat_failures") or [],
        "jurors": [],
        "synthesis": {"majority_verdict": "FALLBACK_REQUIRED"},
    }


def _safe_diagnostic(room_dir: Path, *, returncode: int) -> dict:
    path = room_dir / "launch.failure.json"
    if path.is_file():
        try:
            value = _read_json(path)
            if isinstance(value, dict):
                return value
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    detail = (
        "Agent Room launcher exited before publishing launch.failure.json"
        if returncode
        else "Agent Room launcher did not publish durable readiness evidence"
    )
    return {
        "schema_version": 1,
        "status": "aborted",
        "stage": "launcher",
        "returncode": returncode,
        "seat_failures": [{
            "seat": "launcher",
            "code": "launch_failed" if returncode else "readiness_evidence_missing",
            "detail": detail,
        }],
    }


def _readiness_complete(room_dir: Path) -> bool:
    path = room_dir / "seat-readiness.json"
    if not path.is_file():
        return False
    try:
        readiness = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    ready = {
        str(seat.get("seat_id", "")).removeprefix("seat-").lower()
        for seat in readiness.get("seats") or []
        if seat.get("status") == "ready" and isinstance(seat.get("ready_event_seq"), int)
    }
    return readiness.get("status") == "ready" and ready == set(ROOM_SEATS)


def _enter_room_fallback(
    *,
    room_dir: Path,
    state_path: Path,
    packet_digest: str,
    diagnostic: dict,
) -> dict:
    room_dir.mkdir(parents=True, exist_ok=True)
    artifacts = []
    for path in sorted(room_dir.iterdir()):
        if path.is_file() and path.name != "partial-room.json":
            artifacts.append({
                "path": f"room/{path.name}",
                "sha256": _sha256(path),
                "bytes": path.stat().st_size,
            })
    partial_path = room_dir / "partial-room.json"
    _write_json(partial_path, {
        "schema_version": 1,
        "status": "aborted",
        "merge_forbidden": True,
        "diagnostic": diagnostic,
        "artifacts": artifacts,
    })
    state = start_room_fallback(
        state_path,
        pinned_packet_path="packet.md",
        pinned_packet_digest=packet_digest,
        partial_ledger_path="room/partial-room.json",
        partial_ledger_digest=_sha256(partial_path),
    )
    return _fallback_result(state, diagnostic)


def _advisory_from_ledger(ledger: dict, state: dict) -> dict:
    return {
        "schema_version": 1,
        "panel": "council",
        "lane": "room",
        "status": "complete",
        "room": state["room"],
        "findings": ledger["findings"],
        "dispositions": ledger["dispositions"],
        "receipts": ledger["receipts"],
        "jurors": [],
        "synthesis": {
            "majority_verdict": "ADVISORY_COMPLETE",
            "finding_count": len(ledger["findings"]),
        },
    }


def run_room_advisory(
    *,
    skill: str,
    input_text: str,
    out_dir: str | Path,
    runs_root: str | Path = RUNS_ROOT,
    workspace_root: str | Path | None = None,
    room_binary: str | Path | None = None,
    runner: Runner = subprocess.run,
    acknowledge_link_delivery: bool = False,
) -> dict:
    output = Path(out_dir).resolve()
    root = Path(runs_root).resolve()
    if output.parent != root:
        raise ValueError(f"room review must be an immediate child of canonical runs root: {root}")
    output.mkdir(parents=True, exist_ok=True)
    workspace = Path(workspace_root or Path.cwd()).resolve()
    try:
        output.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("room review directory must be inside the scoped workspace") from exc

    gate = discover_passed_value_gate(root)
    packet_path = output / "packet.md"
    packet_path.write_text(input_text, encoding="utf-8")
    packet_digest = _sha256(packet_path)
    state_path = output / "review.state.json"
    state = _read_json(state_path) if state_path.is_file() else {"schema_version": 1}
    room_dir = output / "room"
    binary = resolve_room_binary(room_binary)

    if state.get("lane") == "room-fallback" and state.get("input_hash") == packet_digest:
        partial = ((state.get("fallback") or {}).get("partial_ledger") or {}).get("path")
        diagnostic = {}
        if partial:
            partial_path = output / partial
            if partial_path.is_file():
                diagnostic = _read_json(partial_path).get("diagnostic") or {}
        return _fallback_result(state, diagnostic)

    resuming_active_room = (
        state.get("lane") == "room"
        and state.get("status") == "room_active"
        and state.get("input_hash") == packet_digest
    )
    if resuming_active_room:
        delivery = state["room"].get("link_delivery")
        if not isinstance(delivery, dict):
            state["room"]["link_delivery"] = _pending_link_delivery(
                state["room"]["watch_url"]
            )
            _write_json(state_path, state)
            return _active_result(state)
        if delivery.get("status") != "acknowledged":
            if not acknowledge_link_delivery:
                return _active_result(state)
            delivery["status"] = "acknowledged"
            delivery["acknowledged_at"] = _now_iso()
            _write_json(state_path, state)

    if state.get("lane") != "room" or state.get("input_hash") != packet_digest:
        if room_dir.exists():
            raise ValueError("room run directory already exists for a different packet")
        relative_packet = packet_path.relative_to(workspace).as_posix()
        command = [
            str(binary),
            "spawn",
            "--run-dir",
            str(room_dir),
            "--room-id",
            _room_id(output),
            "--workspace",
            str(workspace),
            "--seats",
            "claude,codex,minimax",
            "--mode",
            "debate",
            "--scope-ref",
            relative_packet,
            "--readiness-timeout-secs",
            str(READINESS_TIMEOUT_SECS),
            "--no-open",
        ]
        state = {
            "schema_version": 1,
            "skill": skill,
            "status": "room_launching",
            "lane": "room",
            "input_hash": packet_digest,
            "rebuttal": False,
            "dissent_policy": "advocate",
            "peer_phase": "PeerDebate",
            "value_gate": gate,
            "room": {
                "room_id": _room_id(output),
                "run_dir": "room",
                "transcript_path": "room/transcript.jsonl",
                "finding_ledger_path": "room/finding-ledger.json",
                "readiness_path": "room/seat-readiness.json",
                "session_path": "room/seat-sessions.json",
            },
            "auto_memory": True,
        }
        _write_json(state_path, state)
        completed = runner(command, capture_output=True, text=True)
        if completed.returncode != 0 or not _readiness_complete(room_dir):
            if completed.returncode == 0:
                runner(
                    [str(binary), "abort", "--run-dir", str(room_dir)],
                    capture_output=True,
                    text=True,
                )
            diagnostic = _safe_diagnostic(
                room_dir,
                returncode=completed.returncode,
            )
            return _enter_room_fallback(
                room_dir=room_dir,
                state_path=state_path,
                packet_digest=packet_digest,
                diagnostic=diagnostic,
            )
        runtime_path = room_dir / "runtime.json"
        if not runtime_path.is_file():
            runner(
                [str(binary), "abort", "--run-dir", str(room_dir)],
                capture_output=True,
                text=True,
            )
            diagnostic = _safe_diagnostic(
                room_dir,
                returncode=0,
            )
            return _enter_room_fallback(
                room_dir=room_dir,
                state_path=state_path,
                packet_digest=packet_digest,
                diagnostic=diagnostic,
            )
        runtime = _read_json(runtime_path)
        watch_url = f'{runtime["base_url"]}/join/{runtime["pairing_code"]}'
        state = {
            "schema_version": 1,
            "skill": skill,
            "status": "room_active",
            "lane": "room",
            "input_hash": packet_digest,
            "rebuttal": False,
            "dissent_policy": "advocate",
            "peer_phase": "PeerDebate",
            "value_gate": gate,
            "room": {
                "room_id": runtime["room_id"],
                "run_dir": "room",
                "watch_url": watch_url,
                "link_delivery": _pending_link_delivery(watch_url),
                "transcript_path": "room/transcript.jsonl",
                "finding_ledger_path": "room/finding-ledger.json",
                "readiness_path": "room/seat-readiness.json",
                "session_path": "room/seat-sessions.json",
            },
            "auto_memory": True,
        }
        _write_json(state_path, state)
        return _active_result(state)

    ledger_path = room_dir / "finding-ledger.json"
    if not ledger_path.is_file():
        completed = runner(
            [str(binary), "export", "--run-dir", str(room_dir)],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            return _active_result(state)
    transcript_path = room_dir / "transcript.jsonl"
    if not ledger_path.is_file() or not transcript_path.is_file():
        return _active_result(state)

    ledger = _read_json(ledger_path)
    persist_finding_ledger(
        output,
        ledger,
        lane="room",
        transcript_path="room/transcript.jsonl",
    )
    verify_terminal_finding_ledger(output)
    state = _read_json(state_path)
    state.update({
        "skill": skill,
        "status": "awaiting_revision",
        "input_hash": packet_digest,
        "room": state.get("room") or {},
        "auto_memory": True,
    })
    _write_json(state_path, state)
    advisory = _advisory_from_ledger(ledger, state)
    _write_json(output / "council.advisory.json", advisory)
    pin_run_evidence(output, runs_root=root)
    return advisory
