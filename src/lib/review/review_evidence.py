"""Canonical P-1 evidence receipts and the frozen Agent Room value gate."""
from __future__ import annotations

import argparse
import copy
import datetime as _dt
import hashlib
import json
import math
import shutil
import subprocess
from pathlib import Path
from typing import Iterable


RUNS_ROOT = Path(__file__).resolve().parent / ".council-runs"
MANIFEST_NAME = "evidence.manifest.json"
STATE_NAME = "review.state.json"
SAMPLE_NAME = "value-gate.sample.json"

FROZEN_VALUE_GATE = {
    "schema_version": 1,
    "denominator": 3,
    "exclude_self_referential": True,
    "required_loop": 2,
    "material_change": [
        "disposition_action_flip",
        "jury_verdict_tier_change",
        "jury_blocker_add_remove",
    ],
    "max_blocker_inflation": 1.1,
    "correct_minority_erasure_allowed": False,
    "max_escalation_rate_exclusive": 0.5,
    "adjudicator": "the operator",
}


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_run_dir(run_dir: str | Path, runs_root: str | Path) -> tuple[Path, Path]:
    run = Path(run_dir).resolve()
    root = Path(runs_root).resolve()
    if run.parent != root:
        raise ValueError(f"run must be an immediate child of canonical runs root: {root}")
    return run, root


def _artifact_paths(run_dir: Path) -> list[Path]:
    excluded = {run_dir / MANIFEST_NAME, run_dir / STATE_NAME}
    excluded_names = {
        "runtime.json",
        ".serve-config.json",
        "claude-mcp.json",
        "minimax-mcp.json",
        "service.stdout.log",
        "service.stderr.log",
        "room.sqlite3",
        "room.sqlite3-wal",
        "room.sqlite3-shm",
    }
    return sorted(
        (
            path
            for path in run_dir.rglob("*")
            if path.is_file()
            and path not in excluded
            and path.name not in excluded_names
            and not path.name.endswith(".credentials.json")
            and not path.name.endswith(".tmp")
        ),
        key=lambda path: path.relative_to(run_dir).as_posix(),
    )


def pin_run_evidence(
    run_dir: str | Path,
    *,
    runs_root: str | Path = RUNS_ROOT,
) -> dict:
    """Hash every run artifact and record the receipt in state + manifest.

    `review.state.json` and the manifest are intentionally excluded from their own
    digest set, avoiding a self-referential hash.  Every substantive run artifact,
    including the frozen-gate sample, is covered.
    """
    run, _ = _canonical_run_dir(run_dir, runs_root)
    run.mkdir(parents=True, exist_ok=True)
    state_path = run / STATE_NAME
    state = _read_json(state_path) if state_path.is_file() else {"schema_version": 1}
    artifacts = [
        {
            "path": path.relative_to(run).as_posix(),
            "sha256": _sha256(path),
            "bytes": path.stat().st_size,
        }
        for path in _artifact_paths(run)
    ]
    evidence = {
        "schema_version": 1,
        "run_id": run.name,
        "artifact_root": str(run),
        "artifacts": artifacts,
        "pinned_at": _now_iso(),
    }
    state["run_id"] = run.name
    state["evidence"] = copy.deepcopy(evidence)
    state["updated_at"] = _now_iso()
    _write_json(state_path, state)
    manifest = {
        **copy.deepcopy(evidence),
        "state_path": STATE_NAME,
    }
    _write_json(run / MANIFEST_NAME, manifest)
    return manifest


def verify_run_evidence(
    run_dir: str | Path,
    *,
    runs_root: str | Path = RUNS_ROOT,
) -> dict:
    run, _ = _canonical_run_dir(run_dir, runs_root)
    state_path = run / STATE_NAME
    manifest_path = run / MANIFEST_NAME
    if not state_path.is_file() or not manifest_path.is_file():
        return {"ok": False, "mismatches": [{"path": STATE_NAME, "reason": "pin_missing"}]}
    state = _read_json(state_path)
    manifest = _read_json(manifest_path)
    state_evidence = state.get("evidence") or {}
    mismatches: list[dict] = []
    if state_evidence.get("run_id") != run.name or manifest.get("run_id") != run.name:
        mismatches.append({"path": STATE_NAME, "reason": "run_id_mismatch"})
    if state_evidence.get("artifacts") != manifest.get("artifacts"):
        mismatches.append({"path": MANIFEST_NAME, "reason": "state_manifest_mismatch"})

    expected = {item.get("path"): item for item in manifest.get("artifacts") or []}
    actual_paths = {path.relative_to(run).as_posix(): path for path in _artifact_paths(run)}
    for relative, item in expected.items():
        path = actual_paths.get(relative)
        if path is None:
            mismatches.append({"path": relative, "reason": "missing"})
            continue
        if _sha256(path) != item.get("sha256") or path.stat().st_size != item.get("bytes"):
            mismatches.append({"path": relative, "reason": "digest_mismatch"})
    for relative in sorted(set(actual_paths) - set(expected)):
        mismatches.append({"path": relative, "reason": "unpinned"})
    return {
        "ok": not mismatches,
        "run_id": run.name,
        "mismatches": mismatches,
        "artifacts": manifest.get("artifacts") or [],
    }


def schedule_finding(
    state_path: str | Path,
    *,
    finding_id: str,
    source_phase: str,
    owner_phase: str,
    claim: str,
    missing_evidence: str,
    source_ledger_digest: str,
) -> dict:
    if not source_phase or not owner_phase:
        raise ValueError("scheduled finding requires named source and owner phases")
    if len(source_ledger_digest) != 64:
        raise ValueError("scheduled finding requires a SHA-256 source ledger digest")
    path = Path(state_path)
    state = _read_json(path) if path.is_file() else {"schema_version": 1}
    scheduled = state.setdefault("scheduled_findings", [])
    prior = next((item for item in scheduled if item.get("finding_id") == finding_id), None)
    if prior:
        if prior.get("status") == "Open":
            raise ValueError("open finding cannot be rescheduled")
        raise ValueError(f"scheduled finding already exists: {finding_id}")
    record = {
        "finding_id": finding_id,
        "source_phase": source_phase,
        "owner_phase": owner_phase,
        "claim": claim,
        "missing_evidence": missing_evidence,
        "source_ledger_digest": source_ledger_digest,
        "status": "Scheduled",
    }
    scheduled.append(record)
    state["updated_at"] = _now_iso()
    _write_json(path, state)
    return copy.deepcopy(record)


def reconcile_scheduled_findings(
    state_path: str | Path,
    *,
    current_phase: str,
    phase_order: list[str],
) -> dict:
    path = Path(state_path)
    state = _read_json(path)
    current_index = phase_order.index(current_phase) if current_phase in phase_order else None
    escalations = state.setdefault("escalation_queue", [])
    for finding in state.get("scheduled_findings") or []:
        if finding.get("status") != "Scheduled":
            continue
        owner = finding.get("owner_phase")
        if owner not in phase_order:
            finding["status"] = "Escalated"
            if finding["finding_id"] not in escalations:
                escalations.append(finding["finding_id"])
            continue
        owner_index = phase_order.index(owner)
        if current_phase == owner:
            finding["status"] = "Open"
            finding["reentered_at_phase"] = current_phase
        elif current_index is not None and current_index > owner_index:
            finding["status"] = "Escalated"
            if finding["finding_id"] not in escalations:
                escalations.append(finding["finding_id"])
    state["updated_at"] = _now_iso()
    _write_json(path, state)
    return state


def persist_finding_ledger(
    out_dir: str | Path,
    ledger: dict,
    *,
    lane: str = "room",
    transcript_path: str | None = None,
) -> dict:
    """Persist a typed room ledger and bind its digest into review.state.json."""
    if lane not in {"room", "room-fallback"}:
        raise ValueError(f"invalid room lane: {lane}")
    if not isinstance(ledger, dict) or ledger.get("schema_version") != 1:
        raise ValueError("finding ledger schema_version must be 1")
    if not isinstance(ledger.get("findings"), list):
        raise ValueError("finding ledger requires findings: []")
    if not isinstance(ledger.get("dispositions"), list):
        raise ValueError("finding ledger requires dispositions: []")
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    ledger_path = directory / "finding-ledger.json"
    _write_json(ledger_path, ledger)
    digest = _sha256(ledger_path)
    terminal = {"Folded", "Refuted"}
    open_ids = [
        str(finding.get("finding_id"))
        for finding in ledger["findings"]
        if finding.get("status") not in terminal
    ]
    state_path = directory / STATE_NAME
    state = _read_json(state_path) if state_path.is_file() else {"schema_version": 1}
    state.update({
        "lane": lane,
        "finding_ledger": {"path": ledger_path.name, "sha256": digest},
        "open_finding_count": len(open_ids),
        "open_finding_ids": open_ids,
        "updated_at": _now_iso(),
    })
    if transcript_path is not None:
        state["transcript_path"] = transcript_path
    _write_json(state_path, state)
    return state


def verify_terminal_finding_ledger(out_dir: str | Path) -> dict:
    """Fail closed unless the room ledger is digest-valid and every exit accepted."""
    directory = Path(out_dir)
    state_path = directory / STATE_NAME
    if not state_path.is_file():
        raise ValueError("room finding ledger state is missing")
    state = _read_json(state_path)
    descriptor = state.get("finding_ledger") or {}
    relative = descriptor.get("path")
    expected_digest = descriptor.get("sha256")
    if not relative or not expected_digest:
        raise ValueError("room finding ledger receipt is missing")
    ledger_path = (directory / relative).resolve()
    try:
        ledger_path.relative_to(directory.resolve())
    except ValueError as exc:
        raise ValueError("room finding ledger is outside the review directory") from exc
    if not ledger_path.is_file() or _sha256(ledger_path) != expected_digest:
        raise ValueError("room finding ledger digest is invalid")
    ledger = _read_json(ledger_path)
    if ledger.get("schema_version") != 1:
        raise ValueError("room finding ledger schema is invalid")
    findings = ledger.get("findings")
    dispositions = ledger.get("dispositions")
    receipts = ledger.get("receipts")
    if not isinstance(findings, list) or not isinstance(dispositions, list) or not isinstance(receipts, list):
        raise ValueError("room finding ledger structure is invalid")
    receipt_index = {}
    for receipt in receipts:
        if not isinstance(receipt, dict):
            raise ValueError("room finding ledger receipt shape is invalid")
        receipt_id = receipt.get("receipt_id")
        if not receipt_id or receipt_id in receipt_index:
            raise ValueError("room finding ledger receipt id is invalid")
        if receipt.get("kind") not in {"file", "artifact", "measurement", "web", "scope_motion"}:
            raise ValueError(f"room finding ledger receipt kind is invalid: {receipt_id}")
        if not receipt.get("locator"):
            raise ValueError(f"room finding ledger receipt locator is missing: {receipt_id}")
        receipt_index[receipt_id] = receipt
    open_ids = [
        str(finding.get("finding_id"))
        for finding in findings
        if finding.get("status") not in {"Folded", "Refuted"}
    ]
    if open_ids or state.get("open_finding_count") != 0:
        raise ValueError(f"room finding ledger has open findings: {','.join(open_ids)}")
    dispositions_by_finding = {
        disposition.get("finding_id"): disposition for disposition in dispositions
    }
    for finding in findings:
        finding_id = finding.get("finding_id")
        disposition = dispositions_by_finding.get(finding_id)
        if not disposition:
            raise ValueError(f"room finding ledger lacks disposition: {finding_id}")
        if disposition.get("status") not in {"Accepted", "Ruled"}:
            raise ValueError(f"room finding ledger exit is not accepted: {finding_id}")
        receipt_refs = disposition.get("final_receipt_refs") or disposition.get("receipt_refs")
        if not receipt_refs:
            raise ValueError(f"room finding ledger exit lacks receipt: {finding_id}")
        unknown = [
            receipt_id
            for receipt_id in receipt_refs
            if receipt_id not in receipt_index
        ]
        if unknown:
            raise ValueError(f"room finding ledger exit has unknown receipt: {finding_id}")
        if finding.get("status") == "Folded" and not any(
            receipt_index[receipt_id]["kind"] == "artifact"
            for receipt_id in receipt_refs
        ):
            raise ValueError(f"room finding ledger fold lacks artifact receipt: {finding_id}")
    return ledger


def archive_verified_room_memory(
    out_dir: str | Path,
    *,
    scope: str | None = None,
    crypt: str | Path = "crypt",
    runner=subprocess.run,
) -> dict:
    """Archive verdict rationale only after the typed room ledger verifies terminal."""
    directory = Path(out_dir).resolve()
    ledger = verify_terminal_finding_ledger(directory)
    state_path = directory / STATE_NAME
    state = _read_json(state_path)
    ledger_digest = (state.get("finding_ledger") or {}).get("sha256")
    prior = state.get("memory") or {}
    if prior.get("status") == "stored" and prior.get("ledger_sha256") == ledger_digest:
        return prior

    jury_path = directory / "jury.verdict.json"
    jury = _read_json(jury_path) if jury_path.is_file() else {}
    transcript_relative = state.get("transcript_path")
    transcript_digest = None
    if transcript_relative:
        transcript = (directory / transcript_relative).resolve()
        try:
            transcript.relative_to(directory)
        except ValueError as exc:
            raise ValueError("room transcript is outside the review directory") from exc
        if transcript.is_file():
            transcript_digest = _sha256(transcript)

    memory_path = directory / "room-memory.md"
    findings = []
    dispositions = {item.get("finding_id"): item for item in ledger["dispositions"]}
    for finding in ledger["findings"]:
        disposition = dispositions.get(finding.get("finding_id")) or {}
        findings.append(
            f"- {finding.get('claim', finding.get('finding_id'))}: "
            f"{finding.get('status')} ({disposition.get('status')})"
        )
    synthesis = jury.get("synthesis") or {}
    content = "\n".join([
        "---",
        "source: agent-room",
        f"ledger_sha256: {ledger_digest}",
        f"transcript_sha256: {transcript_digest or 'unavailable'}",
        "verified_terminal_ledger: true",
        "---",
        f"# Agent Room verdict — {directory.name}",
        "",
        f"Jury verdict: {synthesis.get('majority_verdict', 'not-yet-recorded')}",
        "",
        "## Finding exits",
        "",
        *findings,
        "",
    ])
    memory_path.write_text(content, encoding="utf-8")
    resolved_scope = scope or str(Path.cwd().resolve()).replace(":", "-").replace("\\", "-").replace("/", "-").strip("-") or "global"
    executable = shutil.which(str(crypt)) or str(crypt)
    command = [
        executable,
        "put",
        f"agent-room-{directory.name}",
        "--scope",
        resolved_scope,
        "--file",
        str(memory_path),
        "--artifact-family",
        "skill_output",
        "--producer",
        "agent_room",
        "--record-type",
        "review_verdict",
    ]
    completed = runner(command, capture_output=True, text=True)
    record = {
        "status": "stored" if completed.returncode == 0 else "failed",
        "ledger_sha256": ledger_digest,
        "transcript_sha256": transcript_digest,
        "path": memory_path.name,
        "scope": resolved_scope,
    }
    if completed.returncode != 0:
        record["error"] = (completed.stderr or "crypt put failed").strip()
    state["memory"] = record
    state["updated_at"] = _now_iso()
    _write_json(state_path, state)
    return record


def _verify_relative_artifact(directory: Path, relative: str, expected_digest: str) -> Path:
    path = (directory / relative).resolve()
    try:
        path.relative_to(directory.resolve())
    except ValueError as exc:
        raise ValueError(f"fallback artifact is outside review directory: {relative}") from exc
    if not path.is_file() or _sha256(path) != expected_digest:
        raise ValueError(f"fallback artifact digest is invalid: {relative}")
    return path


def start_room_fallback(
    state_path: str | Path,
    *,
    pinned_packet_path: str,
    pinned_packet_digest: str,
    partial_ledger_path: str,
    partial_ledger_digest: str,
) -> dict:
    """Seal an aborted room and enter the mandatory two-pass fallback lane."""
    path = Path(state_path)
    directory = path.parent
    state = _read_json(path)
    if state.get("lane") not in {"room", "room-fallback"}:
        raise ValueError("room fallback requires a room lane")
    _verify_relative_artifact(directory, pinned_packet_path, pinned_packet_digest)
    _verify_relative_artifact(directory, partial_ledger_path, partial_ledger_digest)
    state["lane"] = "room-fallback"
    state["status"] = "fallback_required"
    state["fallback"] = {
        "status": "finding_pass_required",
        "pinned_packet": {"path": pinned_packet_path, "sha256": pinned_packet_digest},
        "partial_ledger": {"path": partial_ledger_path, "sha256": partial_ledger_digest},
        "partial_room_sealed": True,
        "merge_forbidden": True,
        "passes": [],
    }
    state["updated_at"] = _now_iso()
    _write_json(path, state)
    return state


def advance_room_fallback(
    state_path: str | Path,
    *,
    completed_pass: str,
    artifact_path: str,
    artifact_digest: str,
    author_acceptance_complete: bool | None = None,
) -> dict:
    path = Path(state_path)
    directory = path.parent
    state = _read_json(path)
    fallback = state.get("fallback") or {}
    if state.get("lane") != "room-fallback" or not fallback.get("merge_forbidden"):
        raise ValueError("room fallback state is invalid")
    _verify_relative_artifact(directory, artifact_path, artifact_digest)
    status = fallback.get("status")
    if completed_pass == "finding" and status == "finding_pass_required":
        next_status = "disposition_check_required"
    elif completed_pass == "disposition_check" and status == "disposition_check_required":
        if author_acceptance_complete is not True:
            raise ValueError("fallback disposition check requires author acceptance")
        next_status = "ready_for_verdict"
    else:
        raise ValueError(f"invalid fallback pass transition: {status}->{completed_pass}")
    fallback.setdefault("passes", []).append({
        "pass": completed_pass,
        "artifact": {"path": artifact_path, "sha256": artifact_digest},
        "author_acceptance_complete": author_acceptance_complete,
    })
    fallback["status"] = next_status
    state["status"] = next_status
    state["updated_at"] = _now_iso()
    _write_json(path, state)
    return state


def _material_changes(sample: dict) -> list[str]:
    blind = sample["blind"]
    debate = sample["peer_debate"]
    changes = []
    blind_dispositions = blind.get("dispositions") or {}
    debate_dispositions = debate.get("dispositions") or {}
    accepted_rejected = {"accepted", "rejected"}
    fold_actions = {"folded", "fold"}
    refute_actions = {"refuted", "refute"}
    disposition_flipped = any(
        (
            {str(blind_dispositions[finding_id]).lower(), str(debate_dispositions[finding_id]).lower()}
            == accepted_rejected
        )
        or (
            str(blind_dispositions[finding_id]).lower() in fold_actions
            and str(debate_dispositions[finding_id]).lower() in refute_actions
        )
        or (
            str(blind_dispositions[finding_id]).lower() in refute_actions
            and str(debate_dispositions[finding_id]).lower() in fold_actions
        )
        for finding_id in set(blind_dispositions) & set(debate_dispositions)
    )
    if disposition_flipped:
        changes.append("disposition_action_flip")
    if blind.get("jury_verdict_tier") != debate.get("jury_verdict_tier"):
        changes.append("jury_verdict_tier_change")
    if set(blind.get("blockers") or []) != set(debate.get("blockers") or []):
        changes.append("jury_blocker_add_remove")
    return changes


def _inflation_ratio(blind_count: int, debate_count: int) -> float:
    if blind_count == 0:
        return 1.0 if debate_count == 0 else math.inf
    return debate_count / blind_count


def _branch_outcome(run_dir: Path) -> dict:
    disposition_path = run_dir / "review.disposition.json"
    jury_path = run_dir / "jury.verdict.json"
    if not disposition_path.is_file() or not jury_path.is_file():
        raise ValueError(f"branch lacks disposition or Jury artifact: {run_dir}")
    disposition = _read_json(disposition_path)
    actions: dict[str, str] = {}
    for index, item in enumerate(disposition.get("advisory_dispositions") or []):
        finding_id = item.get("finding_id") or item.get("finding")
        action = item.get("action")
        if finding_id is None or action is None:
            raise ValueError(f"disposition {index} lacks finding_id/finding or action: {run_dir}")
        key = str(finding_id)
        value = str(action).lower()
        if key in actions and actions[key] != value:
            raise ValueError(f"conflicting disposition for {key}: {run_dir}")
        actions[key] = value

    jury = _read_json(jury_path)
    tier = (jury.get("synthesis") or {}).get("majority_verdict")
    if not tier:
        raise ValueError(f"Jury artifact lacks majority verdict: {run_dir}")
    blockers: set[str] = set()
    for juror in jury.get("jurors") or []:
        if not juror.get("parsed_ok", True):
            continue
        for blocker in juror.get("blockers") or []:
            if isinstance(blocker, str):
                normalized = blocker.strip()
            elif isinstance(blocker, dict) and blocker.get("finding_id"):
                normalized = str(blocker["finding_id"])
            else:
                normalized = json.dumps(blocker, ensure_ascii=False, sort_keys=True)
            if normalized:
                blockers.add(normalized)
    return {
        "dispositions": actions,
        "jury_verdict_tier": str(tier),
        "blockers": sorted(blockers),
    }


def _peer_round_accounting(run_dir: Path) -> dict:
    calls = 0
    tokens = 0
    complete = True
    for name in ("council.rebuttal.json", "council.response.json"):
        path = run_dir / name
        if not path.is_file():
            raise ValueError(f"peer-debate branch lacks {name}: {run_dir}")
        accounting = (_read_json(path).get("accounting") or {})
        call_count = accounting.get("calls")
        total_tokens = (accounting.get("usage") or {}).get("total_tokens")
        if (
            not isinstance(call_count, int) or isinstance(call_count, bool) or call_count < 0
            or not isinstance(total_tokens, int) or isinstance(total_tokens, bool)
            or total_tokens < 0
        ):
            raise ValueError(f"invalid peer-round accounting: {path}")
        calls += call_count
        tokens += total_tokens
        complete = complete and accounting.get("usage_complete") is True
    response = _read_json(run_dir / "council.response.json")
    audit = response.get("resolution_audit") or {}
    resolutions = audit.get("resolutions")
    if not isinstance(resolutions, list) or not resolutions:
        raise ValueError(f"peer response lacks artifact-derived escalation audit: {run_dir}")
    escalation_count = sum(
        1 for resolution in resolutions if resolution.get("outcome") == "unanswered"
    )
    if audit.get("unanswered_count") != escalation_count:
        raise ValueError(f"peer response escalation audit is inconsistent: {run_dir}")
    return {
        "calls": calls,
        "tokens": tokens,
        "usage_source": "provider",
        "usage_complete": complete,
        "escalation_count": escalation_count,
        "escalation_eligible": len(resolutions),
        "escalation_rate": escalation_count / len(resolutions),
    }


def _validate_experiment_pair(blind: Path, debate: Path, review_kind: str) -> None:
    required = ("packet.md", STATE_NAME)
    for directory in (blind, debate):
        for name in required:
            if not (directory / name).is_file():
                raise ValueError(f"branch lacks pinned input identity artifact: {directory / name}")
    blind_state = _read_json(blind / STATE_NAME)
    debate_state = _read_json(debate / STATE_NAME)
    same_packet = _sha256(blind / "packet.md") == _sha256(debate / "packet.md")
    same_input_hash = (
        bool(blind_state.get("input_hash"))
        and blind_state.get("input_hash") == debate_state.get("input_hash")
    )
    if not same_packet or not same_input_hash:
        raise ValueError("gate branches must use the same pinned input packet")
    if blind_state.get("skill") != review_kind or debate_state.get("skill") != review_kind:
        raise ValueError("gate branch review kind does not match")
    if blind_state.get("rebuttal") not in {False, None}:
        raise ValueError("blind branch must not enable peer debate")
    if (
        debate_state.get("rebuttal") is not True
        or debate_state.get("dissent_policy") != "required_contest"
        or debate_state.get("peer_phase") != "PeerDebate"
    ):
        raise ValueError("peer branch lacks predeclared required_contest/PeerDebate condition")


def build_value_gate_sample(
    *,
    run_id: str,
    blind_run_dir: str | Path,
    peer_debate_run_dir: str | Path,
    review_kind: str,
    self_referential: bool,
    operator_adjudication: dict,
    runs_root: str | Path = RUNS_ROOT,
) -> dict:
    """Build one immutable gate sample by copying and pinning both branches."""
    if not run_id or Path(run_id).name != run_id:
        raise ValueError("run_id must be one path-safe segment")
    if operator_adjudication.get("adjudicated_by") != FROZEN_VALUE_GATE["adjudicator"]:
        raise ValueError("value sample requires the operator adjudication")

    blind_source = Path(blind_run_dir).resolve()
    debate_source = Path(peer_debate_run_dir).resolve()
    _validate_experiment_pair(blind_source, debate_source, review_kind)
    blind = _branch_outcome(blind_source)
    debate = _branch_outcome(debate_source)
    accounting = _peer_round_accounting(debate_source)
    output = Path(runs_root).resolve() / run_id
    if output.exists():
        raise ValueError(f"value-gate run already exists: {output}")

    source_files = {
        "blind": (
            blind_source,
            ("packet.md", STATE_NAME, "review.disposition.json", "jury.verdict.json"),
        ),
        "peer_debate": (
            debate_source,
            (
                "packet.md", STATE_NAME, "review.disposition.json", "jury.verdict.json",
                "council.advisory.json", "council.rebuttal.json", "council.response.json",
            ),
        ),
    }
    for _, (directory, names) in source_files.items():
        for name in names:
            if not (directory / name).is_file():
                raise ValueError(f"missing gate source artifact: {directory / name}")

    output.mkdir(parents=True)
    for branch, (directory, names) in source_files.items():
        target = output / branch
        target.mkdir()
        for name in names:
            shutil.copy2(directory / name, target / name)

    sample = {
        "schema_version": 1,
        "run_id": run_id,
        "review_kind": review_kind,
        "self_referential": bool(self_referential),
        "loop": 2,
        "real_review": True,
        "blind": blind,
        "peer_debate": debate,
        "room": accounting,
        "operator_adjudication": copy.deepcopy(operator_adjudication),
    }
    _write_json(output / SAMPLE_NAME, sample)
    _write_json(output / STATE_NAME, {
        "schema_version": 1,
        "run_id": run_id,
        "lane": "p-1-value-gate",
        "status": "complete",
        "updated_at": _now_iso(),
    })
    pin_run_evidence(output, runs_root=runs_root)
    return sample


def evaluate_frozen_value_gate(
    run_dirs: Iterable[str | Path],
    *,
    runs_root: str | Path = RUNS_ROOT,
) -> dict:
    runs = [Path(path).resolve() for path in run_dirs]
    if len(runs) != FROZEN_VALUE_GATE["denominator"]:
        raise ValueError("frozen value gate requires exactly 3 samples")
    if len({run.name for run in runs}) != len(runs):
        raise ValueError("frozen value gate requires 3 distinct run ids")

    rows = []
    failures: set[str] = set()
    for run in runs:
        verification = verify_run_evidence(run, runs_root=runs_root)
        if not verification["ok"]:
            raise ValueError(f"run evidence is not pinned or digest-valid: {run.name}")
        sample_path = run / SAMPLE_NAME
        if not sample_path.is_file():
            raise ValueError(f"missing {SAMPLE_NAME}: {run.name}")
        sample = _read_json(sample_path)
        if sample.get("run_id") != run.name:
            raise ValueError(f"sample run_id mismatch: {run.name}")
        if FROZEN_VALUE_GATE["exclude_self_referential"] and sample.get("self_referential"):
            raise ValueError("self-referential jury-plan packets are excluded from the gate")
        if sample.get("loop") != FROZEN_VALUE_GATE["required_loop"] or not sample.get("real_review"):
            raise ValueError(f"sample is not a real Loop-2 review: {run.name}")
        adjudication = sample.get("operator_adjudication") or {}
        if adjudication.get("adjudicated_by") != FROZEN_VALUE_GATE["adjudicator"]:
            raise ValueError(f"missing the operator adjudication: {run.name}")
        room_metrics = sample.get("room") or {}
        calls = room_metrics.get("calls")
        tokens = room_metrics.get("tokens")
        if (
            not isinstance(calls, int) or isinstance(calls, bool) or calls < 0
            or not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 0
        ):
            raise ValueError(f"room calls/tokens accounting is required: {run.name}")
        usage_source = room_metrics.get("usage_source")
        if (
            room_metrics.get("usage_complete") is not True
            or usage_source not in {"provider", "cli_self_report"}
        ):
            raise ValueError(
                f"room usage must be a complete provider or CLI self-report: {run.name}"
            )

        changes = _material_changes(sample)
        blind_blockers = len(sample["blind"].get("blockers") or [])
        debate_blockers = len(sample["peer_debate"].get("blockers") or [])
        inflation = _inflation_ratio(blind_blockers, debate_blockers)
        minority_erased = bool(adjudication.get("correct_minority_erased"))
        escalation_rate = float(room_metrics.get("escalation_rate", 1.0))
        if inflation > FROZEN_VALUE_GATE["max_blocker_inflation"]:
            failures.add("blocker_inflation")
        if minority_erased:
            failures.add("correct_minority_erased")
        if escalation_rate >= FROZEN_VALUE_GATE["max_escalation_rate_exclusive"]:
            failures.add("majority_escalation")
        rows.append({
            "run_id": run.name,
            "material_changes": changes,
            "blocker_inflation": inflation,
            "correct_minority_erased": minority_erased,
            "escalation_rate": escalation_rate,
            "calls": calls,
            "tokens": tokens,
            "usage_source": usage_source,
        })

    material_count = sum(bool(row["material_changes"]) for row in rows)
    if material_count == 0:
        failures.add("no_material_change")
    return {
        "schema_version": 1,
        "definition": copy.deepcopy(FROZEN_VALUE_GATE),
        "denominator": len(rows),
        "material_change_count": material_count,
        "samples": rows,
        "failures": sorted(failures),
        "passed": not failures,
        "evaluated_at": _now_iso(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pin and verify Council run evidence or evaluate the frozen Agent Room gate.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    pin_parser = subparsers.add_parser("pin")
    pin_parser.add_argument("run_dir")
    pin_parser.add_argument("--runs-root", default=str(RUNS_ROOT))
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("run_dir")
    verify_parser.add_argument("--runs-root", default=str(RUNS_ROOT))
    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("run_dirs", nargs=3)
    evaluate_parser.add_argument("--runs-root", default=str(RUNS_ROOT))
    evaluate_parser.add_argument("--output")
    sample_parser = subparsers.add_parser("sample")
    sample_parser.add_argument("run_id")
    sample_parser.add_argument("--blind-run", required=True)
    sample_parser.add_argument("--peer-debate-run", required=True)
    sample_parser.add_argument("--review-kind", required=True)
    sample_parser.add_argument("--self-referential", action="store_true")
    sample_parser.add_argument("--adjudication", required=True)
    sample_parser.add_argument("--runs-root", default=str(RUNS_ROOT))
    args = parser.parse_args(argv)

    if args.command == "pin":
        result = pin_run_evidence(args.run_dir, runs_root=args.runs_root)
    elif args.command == "verify":
        result = verify_run_evidence(args.run_dir, runs_root=args.runs_root)
    elif args.command == "evaluate":
        result = evaluate_frozen_value_gate(args.run_dirs, runs_root=args.runs_root)
        if args.output:
            _write_json(Path(args.output), result)
    else:
        result = build_value_gate_sample(
            run_id=args.run_id,
            blind_run_dir=args.blind_run,
            peer_debate_run_dir=args.peer_debate_run,
            review_kind=args.review_kind,
            self_referential=args.self_referential,
            operator_adjudication=_read_json(Path(args.adjudication)),
            runs_root=args.runs_root,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.command == "verify":
        return 0 if result["ok"] else 1
    if args.command == "evaluate":
        return 0 if result["passed"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
