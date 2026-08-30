#!/usr/bin/env python3
"""Fail-closed structural validator for zero-context agent dispatches."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import posixpath
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROUTE_VALIDATOR_PATH = (
    Path(__file__).resolve().parents[1]
    / "goalroute"
    / "scripts"
    / "validate-route.py"
)


FORBIDDEN_STORAGE_PARTS = {
    "temp", "tmp", ".tmp", "temporary", "cache", ".cache", "review-run",
    "review-runs", ".review-runs", ".council-runs", "scratch",
}


def clean_path_value(value: str) -> str:
    return value.strip().strip("`").strip('"').strip("'")


def repository_root(path: Path) -> Path | None:
    current = path.resolve()
    if not current.is_dir():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def canonical_locator(path: Path) -> str:
    resolved = path.resolve()
    root = repository_root(resolved)
    if root is None:
        return str(resolved)
    return resolved.relative_to(root).as_posix()


def resolve_declared_path(value: str, artifact: Path) -> Path:
    raw = clean_path_value(value).replace("\\", "/")
    if is_absolute_path(raw):
        return Path(raw).resolve()
    root = repository_root(artifact)
    return ((root or artifact.resolve().parent) / raw).resolve()


def normalized_path(value: str | Path, platform_name: str | None = None) -> str:
    raw = clean_path_value(str(value)).replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", raw):
        normalized = raw.rstrip("/")
    else:
        normalized = str(Path(raw).expanduser().resolve()).replace("\\", "/").rstrip("/")
    return normalized.casefold() if (platform_name or os.name) == "nt" else normalized


def is_absolute_path(value: str) -> bool:
    raw = clean_path_value(value).replace("\\", "/")
    return bool(re.match(r"^[A-Za-z]:/", raw) or raw.startswith("/"))


def storage_errors(
    text: str,
    artifact: Path,
    write_receipt: Path | None,
    verify_receipt: Path | None,
) -> list[str]:
    errors: list[str] = []
    declared_artifact = clean_path_value(
        label_value(text, "**Validated artifact path:**") or ""
    )
    declared_receipt = clean_path_value(label_value(text, "**Receipt path:**") or "")
    actual_artifact = artifact.resolve()
    receipt_arg = write_receipt or verify_receipt

    if not artifact.is_absolute():
        errors.append("validator requires absolute dispatch file path")
    if not declared_artifact:
        errors.append("declared dispatch artifact path is required")
    elif resolve_declared_path(declared_artifact, actual_artifact) != actual_artifact:
        errors.append("declared dispatch artifact path does not match validated file")

    artifact_parts = set(normalized_path(actual_artifact).split("/"))
    if artifact_parts & FORBIDDEN_STORAGE_PARTS or any(
        part.startswith(".validator-") for part in artifact_parts
    ):
        errors.append("canonical dispatch cannot use temporary/cache/review-run storage")
    if actual_artifact.suffix.lower() != ".md":
        errors.append("canonical dispatch must be Markdown")

    if receipt_arg is None:
        errors.append("validation must write or verify sidecar receipt")
        return errors
    if not receipt_arg.is_absolute():
        errors.append("validator requires absolute receipt path")
    if not declared_receipt:
        errors.append("declared receipt path is required")
    elif resolve_declared_path(declared_receipt, actual_artifact) != receipt_arg.resolve():
        errors.append("declared receipt path does not match validator receipt argument")
    if normalized_path(receipt_arg.parent) != normalized_path(actual_artifact.parent):
        errors.append("dispatch receipt must be adjacent to canonical artifact")
    expected_receipt = f"{actual_artifact.stem}.receipt.json"
    if receipt_arg.name != expected_receipt:
        errors.append(f"dispatch receipt must be named {expected_receipt}")
    receipt_parts = set(normalized_path(receipt_arg.resolve()).split("/"))
    if receipt_parts & FORBIDDEN_STORAGE_PARTS or any(
        part.startswith(".validator-") for part in receipt_parts
    ):
        errors.append("dispatch receipt cannot use temporary/cache/review-run storage")
    return errors


def digest_path(value: object, packet: Path, label: str, errors: list[str]) -> Path | None:
    if not isinstance(value, dict) or not isinstance(value.get("path"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(value.get("digest", ""))):
        errors.append(f"{label} requires path and sha256 digest")
        return None
    candidate = resolve_declared_path(value["path"], packet)
    try:
        actual = f"sha256:{hashlib.sha256(candidate.read_bytes()).hexdigest()}"
    except OSError:
        errors.append(f"{label} artifact is missing")
        return None
    if value["digest"] != actual:
        errors.append(f"{label} digest mismatch")
    return candidate


def direct_scope_path(value: str) -> str | None:
    """Return one stable key for a direct-packet scope path.

    Direct packets are portable JSON, so scope comparison cannot depend on
    host filesystem resolution.  Separator and dot-segment aliases still name
    one path, however, and must not create two apparent owners.
    """
    path = value.strip().replace("\\", "/")
    if not path or "\x00" in path or is_absolute_path(path):
        return None
    normalized = posixpath.normpath(path)
    if normalized in {".", ".."} or normalized.startswith("../"):
        return None
    return normalized.casefold() if os.name == "nt" else normalized


def direct_file_allowlist_path(value: str) -> str | None:
    """Return one exact file key for one-touch direct-packet ownership."""
    raw = value.strip().replace("\\", "/")
    normalized = direct_scope_path(raw)
    if (
        normalized is None
        or raw.endswith("/")
        or any(token in raw for token in "*?[")
    ):
        return None
    return normalized


def scope_static_prefix(value: str) -> str:
    parts = value.split("/")
    concrete: list[str] = []
    for part in parts:
        if any(token in part for token in "*?["):
            break
        concrete.append(part)
    return "/".join(concrete)


def scopes_overlap(left: str, right: str) -> bool:
    """Conservatively reject direct OWN scopes with a shared reachable path."""
    if left == right:
        return True
    left_prefix = scope_static_prefix(left)
    right_prefix = scope_static_prefix(right)
    if not left_prefix or not right_prefix:
        return True
    return (
        left_prefix == right_prefix
        or left_prefix.startswith(right_prefix + "/")
        or right_prefix.startswith(left_prefix + "/")
    )


def packet_repository_root(packet: dict, artifact: Path, errors: list[str]) -> Path | None:
    declared = packet.get("repositoryRoot")
    root = resolve_declared_path(declared, artifact) if isinstance(declared, str) else repository_root(artifact)
    if root is None or not root.is_dir() or not (root / ".git").exists():
        errors.append("authority packet requires an existing repository root")
        return None
    return root


def content_reference(
    value: object,
    packet: Path,
    label: str,
    errors: list[str],
    references: list[dict[str, str]],
) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label} requires an artifact path")
        return None
    path = resolve_declared_path(value, packet)
    try:
        digest = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    except OSError:
        errors.append(f"{label} artifact is missing")
        return None
    references.append({"path": canonical_locator(path), "sha256": digest})
    return path


# Executor requirements are optional for legacy direct packets, but every field is
# structural when the proposal's requirement object is supplied.
EXECUTOR_SEMANTIC_REQUIREMENTS = {"forbidden", "conditional", "required"}
EXECUTOR_ESCALATION_OUTCOMES = {
    "unsupported",
    "ambiguous",
    "unreachable",
    "denied",
    "terminated",
    "verification_failed",
    "observation_unavailable",
}
EXECUTOR_TOKEN_RE = re.compile(r"[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*")


def authority_packet_errors(packet: object, artifact: Path) -> tuple[list[str], list[dict[str, str]]]:
    errors: list[str] = []
    references: list[dict[str, str]] = []
    if not isinstance(packet, dict): return ["authority packet must be an object"], references
    required = ("schemaVersion", "kind", "packetType", "sourceRevision", "promptDigest", "modelRouting")
    if any(key not in packet for key in required) or packet.get("schemaVersion") != 1 or packet.get("kind") != "legion-authority-dispatch": errors.append("authority packet base shape is invalid")
    source_revision = packet.get("sourceRevision")
    source_digest = (
        source_revision.removeprefix("git:").removeprefix("sha256:")
        if isinstance(source_revision, str)
        else ""
    )
    if (
        not isinstance(source_revision, str)
        or not re.fullmatch(r"(?:git:)?[0-9a-f]{40}|sha256:[0-9a-f]{64}", source_revision)
        or len(set(source_digest)) == 1
    ):
        errors.append(
            "authority packet source revision must be an immutable git SHA or content digest"
        )
    prompt_digest = str(packet.get("promptDigest", ""))
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", prompt_digest) or len(
        set(prompt_digest.removeprefix("sha256:"))
    ) == 1:
        errors.append("authority packet prompt digest must be a non-placeholder sha256 digest")
    root = packet_repository_root(packet, artifact, errors)
    if isinstance(source_revision, str) and root is not None:
        if source_revision.startswith("sha256:"):
            source_path = content_reference(
                packet.get("sourceArtifact"), artifact, "authority packet source", errors, references
            )
            if source_path is not None:
                actual_source_digest = f"sha256:{hashlib.sha256(source_path.read_bytes()).hexdigest()}"
                if source_revision != actual_source_digest:
                    errors.append("authority packet source revision does not bind source artifact bytes")
        elif re.fullmatch(r"(?:git:)?[0-9a-f]{40}", source_revision):
            revision = source_revision.removeprefix("git:")
            resolved = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--verify", f"{revision}^{{commit}}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if resolved.returncode != 0 or resolved.stdout.strip() != revision:
                errors.append("authority packet source revision does not resolve to repository commit")
    prompt_path = content_reference(
        packet.get("promptArtifact"), artifact, "authority packet prompt", errors, references
    )
    if prompt_path is not None:
        actual_prompt_digest = f"sha256:{hashlib.sha256(prompt_path.read_bytes()).hexdigest()}"
        if prompt_digest != actual_prompt_digest:
            errors.append("authority packet prompt digest does not bind prompt artifact bytes")
    routing = packet.get("modelRouting")
    if not isinstance(routing, dict) or any(not isinstance(routing.get(key), str) or not routing[key] for key in ("modelTier", "workerProfile", "routingRationale")): errors.append("authority packet requires modelTier, workerProfile, routingRationale")
    packet_type = packet.get("packetType")
    def reference(value: object, label: str) -> Path | None:
        path = digest_path(value, artifact, label, errors)
        if path and isinstance(value, dict): references.append({"path": canonical_locator(path), "sha256": value["digest"]})
        return path
    if packet_type == "direct":
        objective = packet.get("objective")
        integration_owner = packet.get("integrationOwner")
        authority = packet.get("authority")
        file_touch_policy = packet.get("fileTouchPolicy")
        dispatches = packet.get("dispatches")
        workers = packet.get("workers")
        oracle_audit = packet.get("oracleAudit")
        recovery = packet.get("recovery")
        if not isinstance(objective, str) or not objective.strip(): errors.append("direct packet requires objective")
        if not isinstance(integration_owner, str) or not integration_owner.strip(): errors.append("direct packet requires integration owner")
        if not isinstance(authority, list) or not authority:
            errors.append("direct packet requires authority sources")
        else:
            for index, authority_path in enumerate(authority, start=1):
                content_reference(
                    authority_path, artifact, f"direct authority {index}", errors, references
                )
        planned_files: set[str] = set()
        if (
            not isinstance(file_touch_policy, dict)
            or file_touch_policy.get("mode") != "once-end-to-end"
            or file_touch_policy.get("allowUnplannedFiles") is not False
            or not isinstance(file_touch_policy.get("plannedFiles"), list)
            or not file_touch_policy.get("plannedFiles")
        ):
            errors.append("direct packet requires closed once-end-to-end file-touch policy")
        else:
            raw_planned = file_touch_policy["plannedFiles"]
            if any(not isinstance(value, str) or not value.strip() for value in raw_planned):
                errors.append("direct plannedFiles requires exact repository-relative file paths")
            else:
                normalized_planned = [direct_file_allowlist_path(value) for value in raw_planned]
                if any(value is None for value in normalized_planned):
                    errors.append("direct plannedFiles forbids globs, directories, and invalid paths")
                planned_files = {value for value in normalized_planned if value is not None}
                if len(planned_files) != len(raw_planned):
                    errors.append("direct plannedFiles contains duplicate or aliased paths")
                if root is not None:
                    for path in planned_files:
                        if (root / path).is_dir():
                            errors.append(f"direct plannedFiles path is a directory: {path}")
        dispatch_ids: set[str] = set()
        dispatch_lanes: dict[str, set[str]] = {}
        declared_lanes: set[str] = set()
        if not isinstance(dispatches, list) or not dispatches:
            errors.append("direct packet requires dependency-ordered dispatch waves")
        else:
            prior_dispatches: set[str] = set()
            for index, dispatch in enumerate(dispatches):
                label = f"direct dispatch {index + 1}"
                if not isinstance(dispatch, dict):
                    errors.append(f"{label} must be an object")
                    continue
                dispatch_id = dispatch.get("id")
                dependencies = dispatch.get("dependsOn")
                lanes = dispatch.get("lanes")
                completion_checks = dispatch.get("completionChecks")
                if not isinstance(dispatch_id, str) or not dispatch_id.strip():
                    errors.append(f"{label} requires id")
                    continue
                if dispatch_id in dispatch_ids:
                    errors.append(f"direct dispatch id is duplicated: {dispatch_id}")
                    continue
                dispatch_ids.add(dispatch_id)
                if (
                    not isinstance(dependencies, list)
                    or any(not isinstance(value, str) or not value.strip() for value in dependencies)
                    or len(set(dependencies)) != len(dependencies)
                ):
                    errors.append(f"{label} dependsOn requires unique prior dispatch ids")
                    dependencies = []
                elif any(value not in prior_dispatches for value in dependencies):
                    errors.append(f"{label} dependsOn must reference only earlier dispatches")
                if index == 0 and dependencies:
                    errors.append("first direct dispatch wave cannot have dependencies")
                if index > 0 and not dependencies:
                    errors.append(f"{label} lacks dependency; move its lanes into first eligible wave")
                if (
                    not isinstance(lanes, list)
                    or not lanes
                    or any(not isinstance(value, str) or not value.strip() for value in lanes)
                    or len(set(lanes)) != len(lanes)
                ):
                    errors.append(f"{label} requires unique lane ids")
                    dispatch_lanes[dispatch_id] = set()
                else:
                    lane_set = set(lanes)
                    overlap = declared_lanes & lane_set
                    if overlap:
                        errors.append(f"direct lanes appear in multiple dispatches: {', '.join(sorted(overlap))}")
                    declared_lanes.update(lane_set)
                    dispatch_lanes[dispatch_id] = lane_set
                if (
                    not isinstance(completion_checks, list)
                    or not completion_checks
                    or any(not isinstance(value, str) or not value.strip() for value in completion_checks)
                ):
                    errors.append(f"{label} requires completion checks")
                prior_dispatches.add(dispatch_id)
        if not isinstance(workers, list) or not workers:
            errors.append("direct packet requires at least one worker")
        else:
            worker_ids: set[str] = set()
            owned_paths: dict[str, str] = {}
            for index, worker in enumerate(workers):
                label = f"direct worker {index + 1}"
                if not isinstance(worker, dict):
                    errors.append(f"{label} must be an object")
                    continue
                worker_id = worker.get("id")
                dispatch_id = worker.get("dispatch")
                executor = worker.get("executor")
                executor_requirement = worker.get("executorRequirement")
                own = worker.get("allowlist")
                read = worker.get("read")
                forbidden = worker.get("forbidden")
                checks = worker.get("checks")
                dependencies = worker.get("dependencies", [])
                if not isinstance(worker_id, str) or not worker_id.strip():
                    errors.append(f"{label} requires id")
                    worker_id = f"#{index + 1}"
                elif worker_id in worker_ids:
                    errors.append(f"direct worker id is duplicated: {worker_id}")
                else:
                    worker_ids.add(worker_id)
                if not isinstance(dispatch_id, str) or dispatch_id not in dispatch_ids:
                    errors.append(f"{label} requires known dispatch wave")
                elif worker_id not in dispatch_lanes.get(dispatch_id, set()):
                    errors.append(f"{label} is not listed in dispatch {dispatch_id}")
                if "executorRequirement" in worker:
                    if not isinstance(executor_requirement, dict):
                        errors.append(f"{label} executorRequirement must be an object")
                    else:
                        semantic_requirement = executor_requirement.get("semanticRequirement")
                        capabilities = executor_requirement.get("capabilities")
                        effects = executor_requirement.get("effects")
                        authority_ceiling = executor_requirement.get("authorityCeiling")
                        completion = executor_requirement.get("completion")
                        escalation = executor_requirement.get("escalation")
                        if semantic_requirement not in EXECUTOR_SEMANTIC_REQUIREMENTS:
                            errors.append(f"{label} executorRequirement has invalid semanticRequirement")
                        for field_name, values in (
                            ("capabilities", capabilities),
                            ("effects", effects),
                            ("authorityCeiling", authority_ceiling),
                        ):
                            if (
                                not isinstance(values, list)
                                or not values
                                or any(
                                    not isinstance(value, str)
                                    or not EXECUTOR_TOKEN_RE.fullmatch(value)
                                    for value in values
                                )
                                or len({value for value in values if isinstance(value, str)}) != len(values)
                            ):
                                errors.append(f"{label} executorRequirement requires valid {field_name}")
                        if (
                            not isinstance(completion, list)
                            or not completion
                            or any(
                                not isinstance(check, dict)
                                or not isinstance(check.get("kind"), str)
                                or not EXECUTOR_TOKEN_RE.fullmatch(check["kind"])
                                or not isinstance(check.get("id"), str)
                                or not check["id"].strip()
                                for check in completion
                            )
                        ):
                            errors.append(f"{label} executorRequirement requires valid completion checks")
                        elif len({check["id"] for check in completion}) != len(completion):
                            errors.append(f"{label} executorRequirement completion ids must be unique")
                        permitted_on: list[object] = []
                        forbidden_on: list[object] = []
                        if not isinstance(escalation, dict):
                            errors.append(f"{label} executorRequirement requires escalation policy")
                        else:
                            permitted_on = escalation.get("permittedOn")
                            forbidden_on = escalation.get("forbiddenOn")
                            for field_name, outcomes in (
                                ("permittedOn", permitted_on),
                                ("forbiddenOn", forbidden_on),
                            ):
                                if (
                                    not isinstance(outcomes, list)
                                    or any(
                                        not isinstance(outcome, str)
                                        or outcome not in EXECUTOR_ESCALATION_OUTCOMES
                                        for outcome in outcomes
                                    )
                                    or len({outcome for outcome in outcomes if isinstance(outcome, str)}) != len(outcomes)
                                ):
                                    errors.append(f"{label} executorRequirement requires valid escalation {field_name}")
                            if (
                                isinstance(permitted_on, list)
                                and isinstance(forbidden_on, list)
                                and all(isinstance(outcome, str) for outcome in permitted_on + forbidden_on)
                            ):
                                if set(permitted_on) & set(forbidden_on):
                                    errors.append(f"{label} executorRequirement escalation policies overlap")
                                if "denied" in permitted_on:
                                    errors.append(f"{label} executorRequirement escalation permits denied")
                                if semantic_requirement == "forbidden" and permitted_on:
                                    errors.append(f"{label} executorRequirement forbids semantic escalation")
                                if semantic_requirement == "conditional" and not permitted_on:
                                    errors.append(f"{label} executorRequirement conditional requires escalation")
                elif not isinstance(executor, str) or not executor.strip():
                    errors.append(f"{label} requires executor")
                scopes = (("OWN", own, True), ("READ", read, False), ("FORBIDDEN", forbidden, False))
                normalized: dict[str, set[str]] = {}
                for scope_name, values, required_scope in scopes:
                    if not isinstance(values, list) or (required_scope and not values) or any(not isinstance(value, str) or not value.strip() for value in values):
                        errors.append(f"{label} requires valid {scope_name} paths")
                        normalized[scope_name] = set()
                    else:
                        path_values = [
                            direct_file_allowlist_path(value) if scope_name == "OWN" else direct_scope_path(value)
                            for value in values
                        ]
                        if any(value is None for value in path_values):
                            if scope_name == "OWN":
                                errors.append(f"{label} allowlist forbids globs, directories, and invalid paths")
                            else:
                                errors.append(f"{label} contains invalid {scope_name} path")
                        normalized[scope_name] = {value for value in path_values if value is not None}
                        if len(normalized[scope_name]) != len(values): errors.append(f"{label} contains duplicate {scope_name} paths")
                if root is not None:
                    for path in normalized["OWN"]:
                        if (root / path).is_dir():
                            errors.append(f"{label} allowlist path is a directory: {path}")
                if normalized["OWN"] & normalized["FORBIDDEN"]: errors.append(f"{label} OWN overlaps FORBIDDEN")
                if normalized["READ"] & normalized["FORBIDDEN"]: errors.append(f"{label} READ overlaps FORBIDDEN")
                for path in normalized["OWN"]:
                    collisions = [
                        (owned_path, owner)
                        for owned_path, owner in owned_paths.items()
                        if scopes_overlap(path, owned_path)
                    ]
                    if collisions:
                        for owned_path, owner in collisions:
                            errors.append(f"direct OWN collision: {path} overlaps {owned_path} owned by {owner} and {worker_id}")
                    else:
                        owned_paths[path] = worker_id
                if not isinstance(checks, list) or not checks or any(not isinstance(value, str) or not value.strip() for value in checks): errors.append(f"{label} requires acceptance checks")
                if not isinstance(dependencies, list) or any(not isinstance(value, str) or not value.strip() for value in dependencies) or len(set(dependencies)) != len(dependencies): errors.append(f"{label} dependencies must be unique worker ids")
            known_ids = {worker.get("id") for worker in workers if isinstance(worker, dict) and isinstance(worker.get("id"), str)}
            if worker_ids != declared_lanes:
                missing = declared_lanes - worker_ids
                extra = worker_ids - declared_lanes
                if missing: errors.append(f"direct dispatch lanes missing workers: {', '.join(sorted(missing))}")
                if extra: errors.append(f"direct workers missing dispatch lane membership: {', '.join(sorted(extra))}")
            owned_file_set = set(owned_paths)
            missing_files = planned_files - owned_file_set
            unplanned_files = owned_file_set - planned_files
            if missing_files:
                errors.append(f"direct planned files lack lane allowlist: {', '.join(sorted(missing_files))}")
            if unplanned_files:
                errors.append(f"direct lane allowlist contains unplanned files: {', '.join(sorted(unplanned_files))}")
            for worker in workers:
                if not isinstance(worker, dict): continue
                worker_id = worker.get("id")
                for dependency in worker.get("dependencies", []) if isinstance(worker.get("dependencies", []), list) else []:
                    if dependency == worker_id: errors.append(f"direct worker {worker_id} cannot depend on itself")
                    elif dependency not in known_ids: errors.append(f"direct worker {worker_id} has unknown dependency: {dependency}")
                    else: errors.append(f"direct lane {worker_id} dependencies belong on dispatch wave, not worker")
        required_oracle_checks = {
            "allowlist-completeness",
            "lane-disjointness",
            "dependency-validity",
            "maximum-safe-parallelization",
            "end-to-end-lane-closure",
        }
        if (
            not isinstance(oracle_audit, dict)
            or oracle_audit.get("required") is not True
            or oracle_audit.get("mode") != "adversarial"
            or oracle_audit.get("status") != "required-before-execution"
            or not isinstance(oracle_audit.get("checks"), list)
            or not required_oracle_checks.issubset(set(oracle_audit.get("checks", [])))
        ):
            errors.append("direct packet requires adversarial Oracle pre-execution audit contract")
        if not isinstance(recovery, dict) or not isinstance(recovery.get("maxRetries"), int) or not 0 <= recovery["maxRetries"] <= 2 or not isinstance(recovery.get("stopConditions"), list) or not recovery["stopConditions"] or any(not isinstance(value, str) or not value.strip() for value in recovery.get("stopConditions", [])) or not isinstance(recovery.get("returnFields"), list) or not recovery["returnFields"] or any(not isinstance(value, str) or not value.strip() for value in recovery.get("returnFields", [])):
            errors.append("direct packet requires bounded recovery and return contract")
    elif packet_type == "sage":
        route = packet.get("routeBundle")
        if not isinstance(route, dict) or not re.search(r"sage-adjudication(?:\.[a-z0-9]+)?$", str(route.get("path", ""))): errors.append("Sage packet requires an exceptional sage-adjudication route bundle")
        else: reference(route, "Sage route bundle")
    elif packet_type in ("oracle", "seer"):
        # "seer" is a read_only_alias per src/config/naming-registry.json; accept and canonicalize.
        lens = packet.get("lens"); scope = packet.get("scope"); oracle = packet.get("oracle")
        if not isinstance(lens, dict) or not lens.get("id"): errors.append("Oracle packet requires lens id")
        else: reference(lens, "Oracle lens")
        if not isinstance(scope, dict) or not isinstance(scope.get("read"), list) or not isinstance(scope.get("forbidden"), list): errors.append("Oracle packet requires read-only scope")
        elif set(scope["read"]) & set(scope["forbidden"]): errors.append("Oracle scope overlaps forbidden paths")
        reference(oracle, "Oracle oracle")
    elif packet_type == "alchemist":
        contract = packet.get("executionContract"); scope = packet.get("scope")
        if not isinstance(contract, dict) or not re.fullmatch(r"EC-\d+", str(contract.get("id", ""))) or contract.get("sealed") is not True or contract.get("executable") is not True: errors.append("Alchemist packet requires sealed executable contract")
        else: reference(contract, "Alchemist execution contract")
        if not isinstance(scope, dict) or not isinstance(scope.get("own"), list) or not isinstance(scope.get("contractOwn"), list) or not set(scope.get("own", [])).issubset(set(scope.get("contractOwn", []))): errors.append("Alchemist OWN scope must be contract subset")
    elif packet_type == "worker":
        capsule = reference(packet.get("workerCapsule"), "Worker capsule")
        if capsule is None: errors.append("worker packet requires canonical WorkerCapsule")
        if not isinstance(packet.get("taskProjection"), dict) or not isinstance(packet.get("artifactProjection"), dict): errors.append("worker packet requires lossless task and artifact projections")
        else:
            reference(packet.get("taskProjection"), "Worker task projection")
            reference(packet.get("artifactProjection"), "Worker artifact projection")
        reference(packet.get("oracle"), "Worker oracle")
    else: errors.append("authority packet type must be direct, sage, oracle, alchemist, or worker")
    if not references:
        errors.append("authority packet requires at least one content-bound artifact")
    return errors, references


REQUIRED_HEADINGS = [
    "# DISPATCH:",
    "## 0. Dispatch Control",
    "## 1. Mission",
    "## 1A. Decision & Experiment Question Lock",
    "## 1B. Authority, Correction & Global Re-Derivation",
    "## 1C. Goal Route & Critical Path",
    "## 1D. Experiment Topology & Workload Funnel",
    "## 2. Source of Truth & Known State",
    "## 3. Scope & Ownership",
    "## 4. Preconditions",
    "## 4A. Execution Path, Reset & Gate Isolation",
    "## 5. Execution Procedure",
    "## 5A. Script & Runner Gate",
    "## 6. Failure Decision & Recovery Matrix",
    "## 7. Verification & Acceptance Map",
    "## 8. Evidence & Artifact Contract",
    "## 9. Return & Integration Contract",
    "## 10. TRUE_BLOCKER Conditions",
    "## 11. Dispatcher Author Gate",
]

REQUIRED_LABELS = [
    "**Dispatch ID:**",
    "**Requester:**",
    "**Dispatcher:**",
    "**Executor:**",
    "**Verifier:**",
    "**Receiver:**",
    "**Mode:**",
    "**Execution host / OS:**",
    "**Shell:**",
    "**Working directory:**",
    "**Repository / branch:**",
    "**Baseline revision:**",
    "**Scoped Git status:**",
    "**User authorization:**",
    "**Dependency position:**",
    "**Parallel safety:**",
    "**Integration owner:**",
    "**Outcome:**",
    "**Definition of done:**",
    "**Non-goals:**",
    "**Task semantics:**",
    "**Primary decision questions:**",
    "**Decision rule:**",
    "**Acceptance metrics only:**",
    "**Diagnostics only:**",
    "**Explicit forbidden scope:**",
    "**Workload / fixture roles:**",
    "**Ground-truth policy:**",
    "**Model / tool relevance rule:**",
    "**Locked model / runtime route:**",
    "**Recovery scope rule:**",
    "**Alchemist gate:**",
    "**Alchemist state reference:**",
    "**Alchemist verification:**",
    "**First-action readback:**",
    "**Supervision cadence:**",
    "**Authority order:**",
    "**Correction state:**",
    "**Correction audit:**",
    "**Plan invalidation:**",
    "**Re-derivation status:**",
    "**Progress disposition:**",
    "**Inherited inventory reconciliation:**",
    "**Alchemist typed-stage binding:**",
    "**State A:**",
    "**State B:**",
    "**Goal success proof:**",
    "**Hard route constraints:**",
    "**Route mode:**",
    "**Selected route:**",
    "**Why fastest valid:**",
    "**Critical path:**",
    "**Bottleneck:**",
    "**Parallel lanes:**",
    "**Deleted / deferred work:**",
    "**Route Alchemist binding:**",
    "**Topology mode:**",
    "**Full-matrix authorization:**",
    "**Value-of-information rule:**",
    "**Declared launch ceiling:**",
    "**Declared minimum wall time:**",
    "**Launch estimate status:**",
    "**Launch-count reconciliation:**",
    "**Supervisor topology checkpoint:**",
    "**Broad selector policy:**",
    "**Authoritative inputs:**",
    "**Known state:**",
    "**Assumptions fixed by dispatcher:**",
    "**Context embedded from chat:**",
    "**Required rules / skills:**",
    "**Required producer / actor:**",
    "**Allowed provenance / lineage:**",
    "**Forbidden producers / substitutes:**",
    "**Existing-work disposition:**",
    "**Required lifecycle chain:**",
    "**Substitution policy:**",
    "**Allowed result derivation:**",
    "**Forbidden result derivation:**",
    "**Lifecycle preflight:**",
    "**OWN — may edit:**",
    "**READ — read only:**",
    "**FORBIDDEN:**",
    "**Dirty-work policy:**",
    "**Side effects / blast radius:**",
    "**Required tools / access:**",
    "**Tool versions:**",
    "**Environment variables:**",
    "**Access / credentials:**",
    "**Required inputs:**",
    "**Preflight command:**",
    "**Critical discriminating invariants:**",
    "**Resume / reset decision:**",
    "**Invalid-window disposition:**",
    "**Authority refresh:**",
    "**Production path chain:**",
    "**Frozen implementation proof:**",
    "**Trace linkage contract:**",
    "**Batch start gate:**",
    "**Defect classification gate:**",
    "**Mid-run authority update protocol:**",
    "**Environment integrity step zero:**",
    "**Canary / one-unit preflight:**",
    "**Script involved:**",
    "**No-script reason:**",
    "**Script ownership:**",
    "**Script path:**",
    "**Creation decision:**",
    "**Script skill:**",
    "**Gate evidence:**",
    "**Final verification command:**",
    "**Output paths:**",
    "**Logs / raw evidence:**",
    "**Hashes / counts / versions:**",
    "**Checkpoint / resume state:**",
    "**Evidence retention:**",
    "**Validated artifact path:**",
    "**Receipt path:**",
    "**Validator command:**",
    "**Receiver hash check:**",
]

STEP_LABELS = [
    "**Route step:**",
    "**Advances target:**",
    "**Dependency order:**",
    "**Purpose:**",
    "**Inputs:**",
    "**Working directory:**",
    "**Exact action / command:**",
    "**Expected stdout / state:**",
    "**Expected exit / result:**",
    "**Timeout / retry:**",
    "**Output artifacts:**",
    "**Evidence to record:**",
    "**On failure:**",
]

FAILURE_CLASSES = [
    "PATH_OR_INPUT_MISSING",
    "TOOL_OR_DEPENDENCY_MISSING",
    "AUTH_OR_PERMISSION_FAILURE",
    "TRANSIENT_EXTERNAL_FAILURE",
    "INVALID_INPUT_OR_SCHEMA",
    "INTEGRITY_OR_HASH_MISMATCH",
    "DETERMINISTIC_COMMAND_FAILURE",
    "DIRTY_OR_CONFLICTING_STATE",
    "WRONG_PRODUCER_OR_PROVENANCE",
    "RESOURCE_OR_CAPACITY_FAILURE",
    "AMBIGUOUS_REQUIREMENT",
    "UNSAFE_OR_OUT_OF_SCOPE_ACTION",
    "UNKNOWN_FAILURE",
]

BYPASS_PATTERNS = {
    "chat-context dependency": r"\b(as discussed|see above|from earlier|existing context|prior[- ](?:thread|chat|conversation) context|earlier[- ](?:thread|chat|conversation)|inherited context|remembered state|implicit credentials?|(?:old|earlier|prior)[- ](?:messages?|session|history))\b",
    "externalized critical meaning": r"\b(?:read|follow)\s+(?:the\s+)?(?:guide|plan|runbook)\b",
    "delegated judgment": r"\b(figure it out|use (your )?best judgment|whatever works)\b",
    "unfinished placeholder": r"\b(TODO|TBD|TK)\b",
    "vague scope": r"\b(relevant files|usual commands|standard checks)\b",
    "optional requirement": r"\b(if needed|if possible|try to)\b",
    "non-operational instruction": r"\b(make it work|clean up|best effort|if appropriate|as needed)\b",
    "vague quality claim": r"\b(ensure|handle|review)\s+(it|things|everything|properly|correctly)\b",
    "uncertain instruction": r"\b(probably|might|soon|later)\b",
}
SECRET_PATTERNS = {
    "OpenAI-like key": r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
    "Slack token": r"\bxox[a-z]-[A-Za-z0-9-]{10,}\b",
    "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
    "private key": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    "literal secret assignment": r"(?i)\b(password|api[_-]?key|secret|token)\s*[:=]\s*[`\"']?[A-Za-z0-9+/=_-]{12,}",
    "authorization header": r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}",
    "bearer credential": r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
}

PLACEHOLDER_RE = re.compile(r"\{\{[^{}\n]+\}\}")
STEP_RE = re.compile(r"(?m)^### Step\s+\d+\s+—\s+.+$")
GENERIC_VALUES = {
    "",
    "fixture-value",
    "value",
    "example",
    "placeholder",
    "tbd",
    "todo",
    "n/a",
    "none",
}
ACTION_RE = re.compile(
    r"\b(run|read|search|inspect|verify|retry|use|capture|preserve|stop|continue|"
    r"compare|fetch|re-fetch|rebuild|isolate|measure|reduce|resume|record|check)\b",
    re.IGNORECASE,
)
PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]|/)[^\s`|]+")
BOUND_RE = re.compile(r"\b\d+\b")
MANAGED_RUST_TOOL_RE = re.compile(r"(?<![\w.-])(cargo|rustc|rustdoc)(?![\w.-])", re.I)


def managed_rust_route_errors(
    text: str,
    artifact_path: Path | None = None,
    route_document: object | None = None,
) -> list[str]:
    """Reject executable Rust tool routes that bypass RightKit.

    Packets are copied verbatim into executor shells.  Treat command-bearing
    Markdown as executable input, not illustrative prose, before a receipt can
    bind it.
    """
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()

    def check(value: str, source: str) -> None:
        for match in MANAGED_RUST_TOOL_RE.finditer(value):
            tool = match.group(1).lower()
            prefix = value[:match.start()]
            if re.search(
                r"(?:^|[\s;&|])rightkit\s+(?:build\s+)?$", prefix, re.I
            ):
                continue
            key = (source, tool)
            if key not in seen:
                seen.add(key)
                errors.append(
                    f"managed Rust route violation in {source}: direct {tool} invocation "
                    f"must use rightkit {tool}"
                )

    # Fenced blocks include explicit command contracts plus stage bindings.
    for index, match in enumerate(
        re.finditer(r"```[^\n]*\n(.*?)\n```", text, re.DOTALL), start=1
    ):
        check(match.group(1), f"fenced block {index}")

    # Inline code is often used for exact commands in source/acceptance prose.
    for index, match in enumerate(re.finditer(r"`([^`\n]+)`", text), start=1):
        check(match.group(1), f"inline code {index}")

    # Markdown table cells & list-label values are executable contract fields.
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("|"):
            for cell_number, cell in enumerate(
                line.strip().strip("|").split("|"), start=1
            ):
                check(cell.strip(), f"table cell {line_number}:{cell_number}")
        label_match = re.match(r"^-\s+\*\*[^*]+:\*\*\s*(.*)$", line)
        if label_match:
            check(label_match.group(1), f"label value {line_number}")

    if route_document is None and artifact_path is not None:
        route_value = label_value(text, "**Goal route artifact:**") or ""
        if route_value:
            try:
                route_document = json.loads(
                    resolve_declared_path(route_value, artifact_path).read_text(
                        encoding="utf-8"
                    )
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                # GoalRoute validation reports unreadable or malformed routes.
                route_document = None
    if isinstance(route_document, dict):
        state_b = route_document.get("state_b")
        proofs = state_b.get("proof") if isinstance(state_b, dict) else None
        if isinstance(proofs, list):
            for index, proof in enumerate(proofs, start=1):
                if isinstance(proof, dict) and isinstance(proof.get("command"), str):
                    check(proof["command"], f"GoalRoute state_b.proof[{index}].command")
    return errors


def ordered_heading_errors(text: str) -> list[str]:
    errors: list[str] = []
    cursor = -1
    for heading in REQUIRED_HEADINGS:
        index = text.find(heading)
        if index < 0:
            errors.append(f"missing heading: {heading}")
        elif index <= cursor:
            errors.append(f"heading out of order: {heading}")
        else:
            cursor = index
    return errors


def label_value(text: str, label: str) -> str | None:
    match = re.search(rf"(?m)^-\s+{re.escape(label)}\s*(.*)$", text)
    return match.group(1).strip() if match else None


LEGACY_AUTHORITY_LABELS = {
    "**Alchemist gate:**": "**Forge gate:**",
    "**Alchemist state reference:**": "**Forge state reference:**",
    "**Alchemist verification:**": "**Forge verification:**",
    "**Alchemist typed-stage binding:**": "**Forge typed-stage binding:**",
    "**Route Alchemist binding:**": "**Route Forge binding:**",
}


def authority_label_value(text: str, label: str) -> str | None:
    value = label_value(text, label)
    if value is not None:
        return value
    legacy = LEGACY_AUTHORITY_LABELS.get(label)
    return label_value(text, legacy) if legacy else None


def is_concrete(value: str) -> bool:
    normalized = value.strip().strip("`").lower()
    return len(normalized) >= 8 and normalized not in GENERIC_VALUES


def fenced_value_after(block: str, label: str) -> str | None:
    match = re.search(
        rf"{re.escape(label)}\s*\n+\s*```[^\n]*\n(.*?)\n```",
        block,
        flags=re.DOTALL,
    )
    return match.group(1).strip() if match else None


def parse_dependency_contract(
    value: str,
) -> tuple[set[str], set[tuple[str, str]]] | None:
    compact = value.replace(" ", "").upper()
    if not compact:
        return None
    roots: set[str] = set()
    edges: set[tuple[str, str]] = set()
    parts = [part for part in compact.split(";") if part]
    for part in parts:
        if part.startswith("START:"):
            roots.update(item for item in part[6:].split(",") if item)
            continue
        if not part.startswith("EDGES:"):
            return None
        chains = [item for item in part[6:].split(",") if item]
        for chain in chains:
            nodes = [item for item in chain.split("->") if item]
            if len(nodes) < 2:
                return None
            edges.update(zip(nodes, nodes[1:]))
            if len(parts) == 1:
                roots.add(nodes[0])
    if not roots:
        targets = {target for _, target in edges}
        roots = {source for source, _ in edges} - targets
    return roots, edges


def exact_action_validator_path_errors(name: str, action: str) -> list[str]:
    invocation_lines = [
        line for line in action.splitlines()
        if "validate-dispatch.py" in line.casefold()
    ]
    if not invocation_lines:
        return []
    invocation_variables = {
        match.group(1).casefold()
        for line in invocation_lines
        for match in re.finditer(r"\$([A-Za-z_]\w*)", line)
    }
    relative_assignment = any(
        match.group(1).casefold() in invocation_variables
        and re.match(r"""["']?(?:tasks|tools)[\\/]""", match.group(2), re.I)
        for match in re.finditer(
            r"""(?im)^\s*\$([A-Za-z_]\w*)\s*=\s*(\S+)""",
            action,
        )
    )
    relative_invocation = any(
        re.search(r"(?:^|\s)(?:tasks|tools)[\\/]", line, re.I)
        for line in invocation_lines
    )
    if relative_assignment or relative_invocation:
        return [f"{name} exact action uses checkout-relative validator paths"]
    return []


def step_errors(text: str, allow_template: bool) -> list[str]:
    matches = list(STEP_RE.finditer(text))
    if not matches:
        return ["missing execution step: expected '### Step N — name'"]

    errors: list[str] = []
    section_end = text.find("## 6. Failure Decision & Recovery Matrix")
    selected_route = (label_value(text, "**Selected route:**") or "").strip("`")
    selected_route = re.sub(r"^SELECTED_ROUTE:\s*", "", selected_route, flags=re.I)
    seen_route_steps: set[str] = set()
    execution_dependencies: dict[str, set[str]] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else section_end
        block = text[match.start():end]
        name = match.group(0)
        for label in STEP_LABELS:
            if label not in block:
                errors.append(f"{name} missing label: {label}")
        action = fenced_value_after(block, "**Exact action / command:**")
        if action is None:
            errors.append(f"{name} missing fenced exact action/command")
        if not allow_template:
            for label in STEP_LABELS:
                if label == "**Exact action / command:**":
                    continue
                value = label_value(block, label)
                if value is None or not is_concrete(value):
                    errors.append(f"{name} has non-concrete value: {label}")
            cwd = label_value(block, "**Working directory:**") or ""
            if not PATH_RE.search(cwd):
                errors.append(f"{name} working directory is not an explicit path")
            if action is not None and (not is_concrete(action) or not ACTION_RE.search(action)):
                errors.append(f"{name} exact action is not executable/actionable")
            if action is not None:
                errors.extend(exact_action_validator_path_errors(name, action))
            timeout = label_value(block, "**Timeout / retry:**") or ""
            if not BOUND_RE.search(timeout):
                errors.append(f"{name} timeout/retry lacks numeric bound")
            for label in ("**Output artifacts:**", "**Evidence to record:**"):
                value = label_value(block, label) or ""
                if not PATH_RE.search(value):
                    errors.append(f"{name} {label} lacks explicit artifact path")
            route_step = label_value(block, "**Route step:**") or ""
            route_match = re.fullmatch(
                r"ROUTE_STEP:([A-Z][A-Z0-9_-]*)/([A-Z][A-Z0-9_-]*)",
                route_step,
                re.I,
            )
            if not route_match:
                errors.append(f"{name} lacks exact ROUTE_STEP binding")
            else:
                route_id = route_match.group(1)
                step_id = f"{route_id}/{route_match.group(2)}".upper()
                if selected_route and route_id.casefold() != selected_route.casefold():
                    errors.append(f"{name} binds non-selected route")
                dependency = label_value(block, "**Dependency order:**") or ""
                if re.match(r"^START:\s*\S", dependency, re.I):
                    execution_dependencies[step_id] = set()
                else:
                    dependency_match = re.match(r"^AFTER:\s*(\S.+)$", dependency, re.I)
                    if not dependency_match:
                        errors.append(
                            f"{name} dependency order must be START or AFTER prior route step"
                        )
                    else:
                        dependencies = {
                            item.strip().upper()
                            for item in re.split(r"[,+]", dependency_match.group(1))
                            if item.strip()
                        }
                        unknown = dependencies - seen_route_steps
                        if unknown:
                            errors.append(
                                f"{name} dependency order references future/unknown route step: "
                                + ", ".join(sorted(unknown))
                            )
                        execution_dependencies[step_id] = dependencies
                seen_route_steps.add(step_id)
            advances = label_value(block, "**Advances target:**") or ""
            if not re.match(r"^ADVANCES_STATE_B:\s*\S", advances, re.I):
                errors.append(f"{name} lacks observable ADVANCES_STATE_B delta")
    if not allow_template:
        route_table = table_rows(
            text,
            "## 1C. Goal Route & Critical Path",
            "## 1D. Experiment Topology & Workload Funnel",
        )
        selected_rows = [
            row for row in route_table[1:]
            if len(row) == 11 and row[9].strip("`").upper() == "SELECTED"
        ]
        if len(selected_rows) == 1:
            declared = re.fullmatch(r"STEPS:(.+)", selected_rows[0][1], re.I)
            declared_steps = {
                item.strip().upper()
                for item in (declared.group(1).split(">") if declared else [])
            }
            if declared_steps != seen_route_steps:
                errors.append(
                    "execution step bindings must exactly cover selected route steps"
                )
            dependency_contract = parse_dependency_contract(selected_rows[0][2])
            if dependency_contract:
                roots, edges = dependency_contract
                expected_dependencies = {
                    step: {source for source, target in edges if target == step}
                    for step in declared_steps
                }
                for root in roots:
                    expected_dependencies.setdefault(root, set())
                if execution_dependencies != expected_dependencies:
                    errors.append(
                        "execution dependency bindings must exactly match selected route DAG"
                    )
    return errors


def table_rows(text: str, start_heading: str, end_heading: str) -> list[list[str]]:
    start = text.find(start_heading)
    end = text.find(end_heading, start + len(start_heading))
    if start < 0 or end < 0:
        return []

    rows: list[list[str]] = []
    for line in text[start:end].splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        rows.append(cells)
    return rows


def table_errors(text: str, allow_template: bool) -> list[str]:
    errors: list[str] = []

    decision_trace = table_rows(
        text,
        "### Requirement-to-decision trace",
        "### Model, tool & dependency relevance",
    )
    errors.extend(
        validate_table(
            "requirement-to-decision trace",
            decision_trace,
            6,
            allow_template,
            {"NONE"},
        )
    )
    model_relevance = table_rows(
        text,
        "### Model, tool & dependency relevance",
        "## 1B. Authority, Correction & Global Re-Derivation",
    )
    errors.extend(
        validate_table("model/tool relevance", model_relevance, 6, allow_template)
    )
    trace_classes: dict[str, str] = {}
    if not allow_template:
        allowed_classes = {
            "ACCEPTANCE",
            "DIAGNOSTIC",
            "EXECUTION_INPUT",
            "SAFETY",
            "FORBIDDEN",
        }
        for row in decision_trace[1:]:
            if len(row) != 6:
                continue
            requirement_id = row[0].strip("`")
            requirement_class = row[1].strip("`")
            trace_classes[requirement_id] = requirement_class
            if requirement_class not in allowed_classes:
                errors.append(
                    f"requirement trace {requirement_id} has invalid class: {requirement_class}"
                )
        for required_id, required_class in (
            ("PRODUCER_IDENTITY", "ACCEPTANCE"),
            ("LIFECYCLE_CHAIN", "ACCEPTANCE"),
            ("NO_SUBSTITUTION", "ACCEPTANCE"),
            ("DIAGNOSTIC_ONLY", "DIAGNOSTIC"),
            ("EXECUTION_INPUT", "EXECUTION_INPUT"),
            ("FORBIDDEN_SCOPE", "FORBIDDEN"),
        ):
            if trace_classes.get(required_id) != required_class:
                errors.append(
                    f"requirement trace missing {required_id} class {required_class}"
                )
        for row in model_relevance[1:]:
            if len(row) != 6:
                continue
            metric_raw = row[1].strip("`")
            metric = metric_raw.upper()
            decision = row[4].strip("`")
            if not re.match(r"^(?:ALLOW|FORBID):\s*\S", decision, re.I):
                errors.append("model/tool relevance decision must be ALLOW: or FORBID:")
            if decision.upper().startswith("ALLOW:") and (
                metric.startswith("NONE") or metric.startswith("N/A")
            ):
                errors.append(
                    "model/tool relevance cannot ALLOW a load that produces no acceptance metric"
                )
            if decision.upper().startswith("ALLOW:"):
                acceptance_metrics = (
                    label_value(text, "**Acceptance metrics only:**") or ""
                ).lower()
                if metric_raw.lower() not in acceptance_metrics:
                    errors.append(
                        "allowed model/tool metric is not named in acceptance metrics"
                    )
                if row[2].strip("`").upper().startswith("NO_MODEL_ALLOWED:"):
                    errors.append(
                        "allowed model/tool conflicts with NO_MODEL_ALLOWED route"
                    )

    inherited_disposition = table_rows(
        text,
        "### Inherited instruction disposition",
        "## 1C. Goal Route & Critical Path",
    )

    errors.extend(
        validate_table(
            "inherited instruction disposition",
            inherited_disposition,
            6,
            allow_template,
            {"NONE", "ALIGNED", "CONFLICTS", "NO_DECISION_VALUE"},
        )
    )

    stage_funnel = table_rows(
        text,
        "### Stage decision funnel",
        "### Typed stage records",
    )
    errors.extend(
        validate_table("stage decision funnel", stage_funnel, 10, allow_template)
    )
    typed_stages = table_rows(
        text,
        "### Typed stage records",
        "### Fixture-stage ownership",
    )
    errors.extend(
        validate_table("typed stage records", typed_stages, 10, allow_template)
    )
    fixture_ownership = table_rows(
        text,
        "### Fixture-stage ownership",
        "## 2. Source of Truth & Known State",
    )
    errors.extend(
        validate_table("fixture-stage ownership", fixture_ownership, 7, allow_template)
    )

    preconditions = table_rows(
        text, "## 4. Preconditions", "## 4A. Execution Path, Reset & Gate Isolation"
    )
    errors.extend(validate_table("preconditions", preconditions, 3, allow_template))

    execution_path = table_rows(
        text, "### Production execution path", "### Gate isolation matrix"
    )
    errors.extend(
        validate_table("production execution path", execution_path, 6, allow_template)
    )
    gate_scope = table_rows(
        text, "### Gate isolation matrix", "### Phase-scoped substitution matrix"
    )
    errors.extend(validate_table("gate isolation matrix", gate_scope, 5, allow_template))
    substitution_scope = table_rows(
        text, "### Phase-scoped substitution matrix", "## 5. Execution Procedure"
    )
    errors.extend(
        validate_table(
            "phase-scoped substitution matrix",
            substitution_scope,
            4,
            allow_template,
        )
    )
    if not allow_template:
        execution_ids = {row[0].strip("`") for row in execution_path[1:] if row}
        for required_stage in (
            "ENTRY_POINT",
            "MORPHER_OR_HOOK",
            "PRODUCER_OR_RUNTIME",
            "DELIVERY",
            "VALUE_OR_ACCEPTANCE",
        ):
            if required_stage not in execution_ids:
                errors.append(
                    f"production execution path missing stage: {required_stage}"
                )
        gate_ids = {row[0].strip("`") for row in gate_scope[1:] if row}
        for required_gate in ("QUALIFICATION_GATE", "END_TO_END_GATE"):
            if required_gate not in gate_ids:
                errors.append(f"gate isolation matrix missing gate: {required_gate}")
        phase_ids = {row[0].strip("`") for row in substitution_scope[1:] if row}
        for required_phase in ("CURRENT_GATE", "OTHER_PHASES"):
            if required_phase not in phase_ids:
                errors.append(
                    f"phase-scoped substitution matrix missing row: {required_phase}"
                )

    evidence = table_rows(
        text, "## 2. Source of Truth & Known State", "## 3. Scope & Ownership"
    )
    errors.extend(validate_table("evidence inventory", evidence, 6, allow_template))

    task_graph = table_rows(text, "## 3. Scope & Ownership", "## 4. Preconditions")
    errors.extend(validate_table("task graph", task_graph, 6, allow_template))

    active = table_rows(text, "## 0. Dispatch Control", "## 1. Mission")
    errors.extend(validate_table("active dispatch inventory", active, 4, allow_template))
    if not allow_template:
        for row in active[1:]:
            if len(row) == 4 and not re.search(r"\b(NO_OVERLAP|SERIALIZED)\b", row[3]):
                errors.append("active dispatch inventory lacks NO_OVERLAP or SERIALIZED decision")

    recovery = table_rows(
        text,
        "## 6. Failure Decision & Recovery Matrix",
        "## 7. Verification & Acceptance Map",
    )
    recovery_data = recovery[1:] if recovery else []
    by_class = {
        cells[0].strip("`"): cells for cells in recovery_data if cells
    }
    for failure_class in FAILURE_CLASSES:
        cells = by_class.get(failure_class)
        if cells is None:
            errors.append(f"missing recovery row: {failure_class}")
            continue
        if len(cells) != 7:
            errors.append(f"recovery row {failure_class} must contain 7 cells")
            continue
        if not allow_template:
            for index, cell in enumerate(cells[1:], start=2):
                if not is_concrete(cell):
                    errors.append(
                        f"recovery row {failure_class} cell {index} is too vague"
                    )
            if "1." not in cells[2] or "2." not in cells[2]:
                errors.append(
                    f"recovery row {failure_class} requires primary + second branch"
                )
            if not ACTION_RE.search(cells[2]) or not ACTION_RE.search(cells[3]):
                errors.append(f"recovery row {failure_class} lacks actionable recovery/degraded path")
            if not BOUND_RE.search(cells[4]):
                errors.append(f"recovery row {failure_class} lacks numeric retry/stop bound")
            if not re.search(r"\b(exit|exists|matches|passes|returns|status|hash|count)\b", cells[5], re.I):
                errors.append(f"recovery row {failure_class} lacks observable proceed condition")
            if "TRUE_BLOCKER" not in cells[6]:
                errors.append(f"recovery row {failure_class} lacks explicit TRUE_BLOCKER threshold")
            escalation = cells[6]
            required_blocker_terms = (
                r"\b(all|every)\b.*\b(branch|recovery|attempt)",
                r"\b(evidence|log|stderr|receipt)\b",
                r"\b(missing input|external input|unblock input)\b",
            )
            if any(
                not re.search(pattern, escalation, re.I)
                for pattern in required_blocker_terms
            ):
                errors.append(
                    f"recovery row {failure_class} TRUE_BLOCKER lacks exhausted-recovery proof"
                )

    acceptance = table_rows(
        text,
        "## 7. Verification & Acceptance Map",
        "## 8. Evidence & Artifact Contract",
    )
    errors.extend(validate_table("acceptance map", acceptance, 5, allow_template))
    if not allow_template:
        acceptance_ids = {
            row[0].strip("`") for row in acceptance[1:] if row
        }
        for required_id in (
            "PRODUCER_IDENTITY",
            "LIFECYCLE_CHAIN",
            "NO_SUBSTITUTION",
        ):
            if required_id not in acceptance_ids:
                errors.append(f"acceptance map missing identity gate: {required_id}")
        for row in acceptance[1:]:
            if len(row) != 5:
                continue
            requirement_id = row[0].strip("`")
            if not PATH_RE.search(row[3]):
                errors.append("acceptance row lacks explicit evidence path")
            if trace_classes.get(requirement_id) != "ACCEPTANCE":
                errors.append(
                    f"acceptance requirement lacks ACCEPTANCE decision trace: {requirement_id}"
                )

    return errors


def validate_table(
    name: str,
    rows: list[list[str]],
    width: int,
    allow_template: bool,
    concrete_exceptions: set[str] | None = None,
) -> list[str]:
    if len(rows) < 2:
        return [f"{name} requires at least one data row"]
    errors: list[str] = []
    for index, row in enumerate(rows[1:], start=1):
        if len(row) != width:
            errors.append(f"{name} row {index} must contain {width} cells")
            continue
        if not allow_template:
            for cell_index, cell in enumerate(row, start=1):
                normalized = cell.strip().strip("`").upper()
                if not is_concrete(cell) and normalized not in (
                    concrete_exceptions or set()
                ):
                    errors.append(f"{name} row {index} cell {cell_index} is too vague")
    return errors


def script_gate_values(text: str) -> dict[str, str]:
    start = text.find("## 5A. Script & Runner Gate")
    end = text.find("## 6. Failure Decision & Recovery Matrix", start)
    if start < 0 or end < 0:
        return {}
    block = text[start:end]
    gate = fenced_value_after(block, "**Gate evidence:**") or ""
    values: dict[str, str] = {}
    for line in gate.splitlines():
        match = re.match(
            r"^(GOAL|SELECTED_PATH|WHY_FASTEST_VALID|BOTTLENECK|PARALLEL|"
            r"DEFERRED|GOAL_ROUTE_ARTIFACT|GOAL_ROUTE_RECEIPT|"
            r"EXPECTED_TIME_TO_VERIFIED_B_MS|ROUTE_REVISION|"
            r"TIER|PRE|SMOKE|CHECK|BLAST|OPT|SHIP):\s*(.+)$",
            line.strip(),
        )
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


def goal_route_errors(
    text: str, allow_template: bool, artifact_path: Path | None = None
) -> list[str]:
    if allow_template:
        return []
    errors: list[str] = []
    rules = (
        ("**State A:**", r"^STATE_A:\s*\S"),
        ("**State B:**", r"^STATE_B:\s*\S"),
        ("**Goal success proof:**", r"^PROOF:\s*\S"),
        ("**Hard route constraints:**", r"^CONSTRAINTS:\s*\S"),
        ("**Goal route schema:**", r"^goal-route\.v2$"),
        ("**Selected route:**", r"^SELECTED_ROUTE:\s*[A-Z][A-Z0-9_-]*$"),
        (
            "**Expected time to verified B:**",
            r"^EXPECTED_TIME_TO_VERIFIED_B_MS:\d+$",
        ),
        ("**Route revision:**", r"^ROUTE_REVISION:[1-9]\d*$"),
        ("**Why fastest valid:**", r"^EXPECTED_TIME_PROOF:\s*\S"),
        ("**Bottleneck:**", r"^BOTTLENECK:\s*\S"),
        (
            "**Parallel lanes:**",
            r"^(?:PARALLEL:\s*\S|NONE_DEPENDENCY_BOUND:\s*\S)",
        ),
        (
            "**Deleted / deferred work:**",
            r"^DELETE:\s*\S.+;\s*DEFER:\s*\S",
        ),
    )
    for label, pattern in rules:
        if not re.match(pattern, label_value(text, label) or "", re.I):
            errors.append(f"{label} lacks enforceable goal-route contract")
    for label in ("**State A:**", "**State B:**"):
        state = (label_value(text, label) or "").split(":", 1)[-1]
        if not is_concrete(state):
            errors.append(f"{label} requires concrete state, not label-only value")
    proof = label_value(text, "**Goal success proof:**") or ""
    if not ACTION_RE.search(proof) or not PATH_RE.search(proof):
        errors.append("Goal success proof requires executable action + evidence path")
    constraints = (label_value(text, "**Hard route constraints:**") or "").upper()
    for token in ("AUTHORITY", "SAFETY", "SCOPE", "COST", "QUALITY"):
        if token not in constraints:
            errors.append(f"Hard route constraints missing {token}")
    if not BOUND_RE.search(label_value(text, "**Bottleneck:**") or ""):
        errors.append("Bottleneck requires numeric critical-path bound")

    mode = (label_value(text, "**Route mode:**") or "").strip("`").upper()
    if mode not in {"COMPARE", "SINGLE_FEASIBLE"}:
        errors.append("Route mode must be COMPARE or SINGLE_FEASIBLE")

    route_path_value = label_value(text, "**Goal route artifact:**") or ""
    receipt_path_value = label_value(text, "**Goal route receipt:**") or ""
    if not route_path_value:
        errors.append("Goal route artifact path is required")
    if not receipt_path_value:
        errors.append("Goal route receipt path is required")

    route_document: dict[str, object] | None = None
    route_candidates: dict[str, dict[str, object]] = {}
    if route_path_value and receipt_path_value and artifact_path is not None:
        route_path = resolve_declared_path(route_path_value, artifact_path)
        receipt_path = resolve_declared_path(receipt_path_value, artifact_path)
        try:
            raw = route_path.read_bytes()
            parsed_route = json.loads(raw.decode("utf-8"))
            spec = importlib.util.spec_from_file_location(
                "dispatch_goal_route_validator", ROUTE_VALIDATOR_PATH
            )
            if spec is None or spec.loader is None:
                raise RuntimeError("cannot load shared GoalRoute validator")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            errors.extend(
                f"GoalRoute artifact: {error}"
                for error in module.validate_route(parsed_route)
            )
            errors.extend(
                f"GoalRoute receipt: {error}"
                for error in module.validate_receipt(route_path, receipt_path, raw)
            )
            if isinstance(parsed_route, dict):
                route_document = parsed_route
                route_candidates = {
                    str(candidate.get("id", "")): candidate
                    for candidate in route_document.get("candidates", [])
                    if isinstance(candidate, dict)
                }
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError) as exc:
            errors.append(f"GoalRoute artifact/receipt cannot be validated: {exc}")

    table = table_rows(
        text,
        "## 1C. Goal Route & Critical Path",
        "## 1D. Experiment Topology & Workload Funnel",
    )
    raw_rows = table[1:]
    for index, row in enumerate(raw_rows, start=1):
        if len(row) != 11:
            errors.append(f"goal route comparison row {index} must contain 11 cells")
    rows = [row for row in raw_rows if len(row) == 11]
    if mode == "COMPARE" and not 2 <= len(rows) <= 3:
        errors.append("COMPARE route mode requires 2-3 candidate routes")
    if mode == "SINGLE_FEASIBLE" and len(rows) != 1:
        errors.append("SINGLE_FEASIBLE route mode requires exactly one candidate route")

    selected_label = re.sub(
        r"^SELECTED_ROUTE:\s*",
        "",
        label_value(text, "**Selected route:**") or "",
        flags=re.I,
    ).strip("` ")
    route_data: list[dict[str, object]] = []
    route_ids: list[str] = []
    for row in rows:
        route_id = row[0].strip("`")
        route_ids.append(route_id)
        steps_match = re.fullmatch(
            rf"STEPS:({re.escape(route_id)}/[A-Z][A-Z0-9_-]*"
            rf"(?:>{re.escape(route_id)}/[A-Z][A-Z0-9_-]*)*)",
            row[1],
            re.I,
        )
        if not steps_match:
            errors.append(f"route {route_id} requires ordered STEPS bound to route ID")
            step_ids: list[str] = []
        else:
            step_ids = [item.upper() for item in steps_match.group(1).split(">")]
        dependency_contract = parse_dependency_contract(row[2])
        if dependency_contract is None:
            errors.append(f"route {route_id} requires explicit dependency edges")
            route_roots: set[str] = set()
            route_edges: set[tuple[str, str]] = set()
        else:
            route_roots, route_edges = dependency_contract
            graph_steps = route_roots | {
                node for edge in route_edges for node in edge
            }
            if step_ids and graph_steps != set(step_ids):
                errors.append(
                    f"route {route_id} dependency graph must exactly cover ordered steps"
                )
        constraint_pass = bool(re.match(r"^PASS:\s*\S", row[3], re.I))
        constraint_fail = bool(re.match(r"^FAIL:\s*\S", row[3], re.I))
        if not (constraint_pass or constraint_fail):
            errors.append(f"route {route_id} constraint result must be PASS or FAIL")
        numeric: list[int] = []
        for index, label in zip(
            range(4, 9), ("wall", "expected", "cost", "risk", "rework")
        ):
            if not re.fullmatch(r"\d+", row[index].strip("` ")):
                errors.append(f"route {route_id} {label} units must be integer")
                numeric.append(0)
            else:
                numeric.append(int(row[index].strip("` ")))
        status = row[9].strip("`").upper()
        if status not in {"SELECTED", "REJECTED"}:
            errors.append(f"route {route_id} status must be SELECTED or REJECTED")
        if status == "SELECTED" and not constraint_pass:
            errors.append(f"selected route {route_id} must pass hard constraints")
        if status == "REJECTED" and constraint_pass and not re.match(
            rf"^(?:DOMINATED_BY:{re.escape(selected_label)}|TRADEOFF:)\s*\S",
            row[10],
            re.I,
        ):
            errors.append(
                f"passing rejected route {route_id} requires dominance/tradeoff evidence"
            )
        if mode == "SINGLE_FEASIBLE" and not re.match(
            r"^ONLY_FEASIBLE:EVIDENCE:\s*\S",
            row[10],
            re.I,
        ):
            errors.append("SINGLE_FEASIBLE route requires ONLY_FEASIBLE evidence")
        if "EVIDENCE:" not in row[10].upper() or not PATH_RE.search(row[10]):
            errors.append(f"route {route_id} requires evidence path")
        route_data.append({
            "id": route_id,
            "steps": step_ids,
            "roots": route_roots,
            "edges": route_edges,
            "pass": constraint_pass,
            "wall": numeric[0],
            "expected": numeric[1],
            "cost": numeric[2],
            "risk": numeric[3],
            "rework": numeric[4],
            "status": status,
        })

    if len(route_ids) != len(set(route_ids)):
        errors.append("goal route comparison contains duplicate route IDs")
    selected = [route for route in route_data if route["status"] == "SELECTED"]
    if len(selected) != 1:
        errors.append("goal route comparison requires exactly one SELECTED route")
    elif str(selected[0]["id"]).casefold() != selected_label.casefold():
        errors.append("Selected route label does not match SELECTED route row")

    if route_document is not None:
        artifact_mode = str(route_document.get("comparison_mode", ""))
        if artifact_mode != mode:
            errors.append("Route mode must match GoalRoute artifact")
        if set(route_ids) != set(route_candidates):
            errors.append("route table IDs must exactly match GoalRoute artifact candidates")
        artifact_selected_id = str(route_document.get("selected_route_id", ""))
        if artifact_selected_id.casefold() != selected_label.casefold():
            errors.append("Selected route must match GoalRoute artifact")
        expected_label = re.sub(
            r"^EXPECTED_TIME_TO_VERIFIED_B_MS:",
            "",
            label_value(text, "**Expected time to verified B:**") or "",
            flags=re.I,
        )
        revision_label = re.sub(
            r"^ROUTE_REVISION:",
            "",
            label_value(text, "**Route revision:**") or "",
            flags=re.I,
        )
        invalidation = route_document.get("invalidation", {})
        artifact_revision = (
            invalidation.get("revision")
            if isinstance(invalidation, dict)
            else None
        )
        artifact_correction = (
            str(invalidation.get("semantic_correction", ""))
            if isinstance(invalidation, dict)
            else ""
        )
        dispatch_correction = label_value(text, "**Correction state:**") or ""
        if artifact_correction == "NONE" and not re.match(
            r"^NONE:", dispatch_correction, re.I
        ):
            errors.append("dispatch correction state must match GoalRoute artifact")
        if artifact_correction == "RECOMPILED_FROM_ROOT" and not re.match(
            r"^SEMANTIC_CORRECTION:", dispatch_correction, re.I
        ):
            errors.append("dispatch correction state must match GoalRoute artifact")
        selected_artifact = route_candidates.get(artifact_selected_id, {})
        if expected_label != str(
            selected_artifact.get("expected_time_to_verified_b_ms", "")
        ):
            errors.append("Expected time label must match selected GoalRoute candidate")
        if revision_label != str(artifact_revision):
            errors.append("Route revision label must match GoalRoute artifact")
        for route in route_data:
            artifact = route_candidates.get(str(route["id"]))
            if not artifact:
                continue
            artifact_steps = {
                str(step.get("id", "")).upper(): step
                for step in artifact.get("steps", [])
                if isinstance(step, dict)
            }
            artifact_roots = {
                step_id
                for step_id, step in artifact_steps.items()
                if not step.get("depends_on")
            }
            artifact_edges = {
                (str(source).upper(), step_id)
                for step_id, step in artifact_steps.items()
                for source in step.get("depends_on", [])
            }
            if set(route["steps"]) != set(artifact_steps):
                errors.append(
                    f"route {route['id']} steps must match GoalRoute artifact"
                )
            if route["roots"] != artifact_roots or route["edges"] != artifact_edges:
                errors.append(
                    f"route {route['id']} dependency DAG must match GoalRoute artifact"
                )
            mirrors = (
                ("wall", "nominal_critical_path_ms"),
                ("expected", "expected_time_to_verified_b_ms"),
                ("cost", "cost_units"),
                ("risk", "risk_units"),
                ("rework", "rework_units"),
                ("status", "status"),
            )
            for inline_key, artifact_key in mirrors:
                if route[inline_key] != artifact.get(artifact_key):
                    errors.append(
                        f"route {route['id']} {inline_key} must match GoalRoute artifact"
                    )

    if selected:
        winner = selected[0]
        critical = label_value(text, "**Critical path:**") or ""
        critical_match = re.fullmatch(
            r"CRITICAL_PATH:([^;]+);\s*TOTAL_MIN_WALL_MS:(\d+)",
            critical,
            re.I,
        )
        if not critical_match:
            errors.append("Critical path requires ordered steps + TOTAL_MIN_WALL_MS")
        else:
            critical_steps = [
                item.strip().upper() for item in critical_match.group(1).split(">")
            ]
            if not critical_steps or not set(critical_steps) <= set(winner["steps"]):
                errors.append("Critical path steps must belong to selected route")
            if int(critical_match.group(2)) != int(winner["wall"]):
                errors.append(
                    "Critical path TOTAL_MIN_WALL_MS must equal selected route wall"
                )
            if route_document is not None:
                artifact_path = [
                    str(item).upper()
                    for item in route_document.get("selected_critical_path", [])
                ]
                if critical_steps != artifact_path:
                    errors.append("Critical path must exactly match GoalRoute artifact")

    alchemist_gate = authority_label_value(text, "**Alchemist gate:**") or ""
    route_alchemist = authority_label_value(text, "**Route Alchemist binding:**") or ""
    artifact_alchemist = {}
    state_scheme = "alchemist"
    if isinstance(route_document, dict):
        if isinstance(route_document.get("alchemist"), dict):
            artifact_alchemist = route_document["alchemist"]
        elif isinstance(route_document.get("forge"), dict):
            artifact_alchemist = route_document["forge"]
            state_scheme = "forge"
    if isinstance(artifact_alchemist, dict) and artifact_alchemist.get("required"):
        run_id = str(artifact_alchemist.get("run_id", ""))
        expected = (
            f"SCHEMA:goal-route.v2; RUN_ID:{run_id}; "
            f"STATE:{state_scheme}://run/{run_id}/state; CHECKPOINT:GOAL_ROUTE_V2"
        )
        if route_alchemist.casefold() != expected.casefold():
            errors.append("Route Alchemist binding must match GoalRoute artifact")
        if run_id not in alchemist_gate:
            errors.append("dispatch Alchemist gate must contain GoalRoute Alchemist run ID")
    elif not re.match(
        r"^SCHEMA:goal-route\.v2;\s*NOT_REQUIRED:\s*\S", route_alchemist, re.I
    ):
        errors.append("routine route Alchemist binding requires NOT_REQUIRED reason")
    return errors


def status_errors(text: str) -> list[str]:
    errors: list[str] = []
    allowed = {
        "COMPLETE",
        "COMPLETE_WITH_NOTES",
        "TRUE_BLOCKER",
        "COMPLETE | COMPLETE_WITH_NOTES | TRUE_BLOCKER",
    }
    values = re.findall(r"(?m)^STATUS:\s*(.+)$", text)
    if len(values) != 1:
        errors.append("return contract requires exactly one STATUS line")
    for value in values:
        if value.strip() not in allowed:
            errors.append(f"forbidden terminal status: {value.strip()}")
    return errors


def execution_identity_errors(text: str, allow_template: bool) -> list[str]:
    if allow_template:
        return []

    errors: list[str] = []
    rules = (
        ("**Required producer / actor:**", r"^PRODUCER:\s*\S.+\bPROOF_FIELD:\s*\S"),
        ("**Allowed provenance / lineage:**", r"^ALLOW_ONLY:\s*\S"),
        (
            "**Forbidden producers / substitutes:**",
            r"^(?:FORBID:\s*\S|NONE_CHECKED\s+—\s+\S)",
        ),
        (
            "**Existing-work disposition:**",
            r"\bINVENTORY:\s*\S.+\bREJECT_IF_INCOMPATIBLE:\s*\S.+\bRESUME_ONLY_IF:\s*\S",
        ),
        (
            "**Substitution policy:**",
            r"^(?:NO_SUBSTITUTION\b|ALLOWED_EQUIVALENTS:\s*\S)",
        ),
        ("**Allowed result derivation:**", r"^DIRECT_ONLY:\s*\S"),
        ("**Forbidden result derivation:**", r"^FORBID:\s*\S"),
    )
    for label, pattern in rules:
        value = label_value(text, label) or ""
        if not re.search(pattern, value, re.I):
            errors.append(f"{label} lacks enforceable identity/provenance contract")

    lifecycle = label_value(text, "**Required lifecycle chain:**") or ""
    if not lifecycle.startswith("LIFECYCLE:") or lifecycle.count("->") < 4:
        errors.append(
            "**Required lifecycle chain:** requires LIFECYCLE plus at least five ordered states"
        )

    preflight = fenced_value_after(text, "**Lifecycle preflight:**") or ""
    if (
        not is_concrete(preflight)
        or not ACTION_RE.search(preflight)
        or not PATH_RE.search(preflight)
    ):
        errors.append(
            "**Lifecycle preflight:** requires exact action/command plus evidence path"
        )
    return errors


def execution_control_errors(text: str, allow_template: bool) -> list[str]:
    if allow_template:
        return []

    errors: list[str] = []
    invariants = label_value(text, "**Critical discriminating invariants:**") or ""
    if invariants.count("INVARIANT:") < 3:
        errors.append(
            "**Critical discriminating invariants:** requires at least three embedded INVARIANT entries"
        )

    rules = (
        (
            "**Resume / reset decision:**",
            r"^(?:RESET_REQUIRED:|RESUME_ALLOWED_IF:)\s*\S",
        ),
        (
            "**Invalid-window disposition:**",
            r"\bSTOP\b.*\b(?:DISCARD|PRESERVE)\b.*\bDO_NOT_COMMIT\b",
        ),
        ("**Authority refresh:**", r"^AUTHORITY_REFRESH:\s*\S"),
        ("**Frozen implementation proof:**", r"^HASH_VERIFY:\s*\S"),
        ("**Batch start gate:**", r"^PROHIBITED_UNTIL_CANARY_PASS\b"),
        (
            "**Defect classification gate:**",
            r"^DEFECT_ONLY_IF:.*\bPRODUCTION_PATH_PROVEN\b.*\bCANARY_PASS\b.*\bCANONICAL_CHECK_FAILS\b",
        ),
        (
            "**Mid-run authority update protocol:**",
            r"^STOP\s*->\s*DISCARD_INVALID_WINDOW\s*->\s*PULL_AUTHORITY\s*->\s*REVERIFY\s*->\s*RESTART_PREFLIGHT$",
        ),
    )
    for label, pattern in rules:
        value = label_value(text, label) or ""
        if not re.search(pattern, value, re.I):
            errors.append(f"{label} lacks enforceable execution-control contract")

    production_path = label_value(text, "**Production path chain:**") or ""
    if not production_path.startswith("PRODUCTION_PATH:") or production_path.count(
        "->"
    ) < 4:
        errors.append(
            "**Production path chain:** requires PRODUCTION_PATH plus at least five ordered stages"
        )
    trace_link = label_value(text, "**Trace linkage contract:**") or ""
    if not trace_link.startswith("TRACE_LINK:") or trace_link.count("->") < 4:
        errors.append(
            "**Trace linkage contract:** requires TRACE_LINK across expected, started, terminal, delivery, & value"
        )

    for label in (
        "**Environment integrity step zero:**",
        "**Canary / one-unit preflight:**",
    ):
        command = fenced_value_after(text, label) or ""
        if (
            not is_concrete(command)
            or not ACTION_RE.search(command)
            or not PATH_RE.search(command)
        ):
            errors.append(f"{label} requires exact action/command plus evidence path")
    return errors


def decision_scope_errors(text: str, allow_template: bool) -> list[str]:
    if allow_template:
        return []

    errors: list[str] = []
    semantics_raw = label_value(text, "**Task semantics:**") or ""
    semantics = {
        token
        for token in re.split(r"[\s,|/+]+", semantics_raw.upper())
        if token
    }
    allowed_semantics = {
        "ROUTINE",
        "EXPERIMENT",
        "BENCHMARK",
        "PERFORMANCE",
        "MODEL",
        "RESEARCH",
        "REPEATED_FAILURE",
    }
    if not semantics or not semantics <= allowed_semantics:
        errors.append(
            "**Task semantics:** must use only ROUTINE, EXPERIMENT, BENCHMARK, PERFORMANCE, MODEL, RESEARCH, or REPEATED_FAILURE"
        )

    rules = (
        ("**Primary decision questions:**", r"\bQUESTION_1:\s*\S"),
        ("**Decision rule:**", r"^DECIDE_BY:\s*\S"),
        ("**Acceptance metrics only:**", r"^METRICS_ONLY:\s*\S"),
        ("**Diagnostics only:**", r"^DIAGNOSTIC_ONLY:\s*\S"),
        ("**Explicit forbidden scope:**", r"^FORBID:\s*\S"),
        ("**Workload / fixture roles:**", r"^WORKLOAD_ROLE:\s*\S"),
        (
            "**Ground-truth policy:**",
            r"^GROUND_TRUTH_SOURCE:\s*\S.*\bMEASURED_OUTPUT_NOT_GROUND_TRUTH\b",
        ),
        ("**Model / tool relevance rule:**", r"^LOAD_ONLY_IF_METRIC:\s*\S"),
        (
            "**Locked model / runtime route:**",
            r"^(?:ROUTE_LOCK:|NO_MODEL_ALLOWED:)\s*\S",
        ),
        ("**Recovery scope rule:**", r"^NO_SCOPE_EXPANSION:\s*\S"),
        ("**First-action readback:**", r"^READBACK_REQUIRED:\s*\S"),
        (
            "**Supervision cadence:**",
            r"^SUPERVISE:\s*.*\b\d+\b.*\b(?:minute|unit|step|action|command)s?\b",
        ),
    )
    for label, pattern in rules:
        value = label_value(text, label) or ""
        if not re.search(pattern, value, re.I):
            errors.append(f"{label} lacks enforceable decision-scope contract")

    alchemist_required = bool(
        semantics
        & {
            "EXPERIMENT",
            "BENCHMARK",
            "PERFORMANCE",
            "MODEL",
            "RESEARCH",
            "REPEATED_FAILURE",
        }
    )
    alchemist_gate = authority_label_value(text, "**Alchemist gate:**") or ""
    alchemist_state = authority_label_value(text, "**Alchemist state reference:**") or ""
    alchemist_verify = authority_label_value(text, "**Alchemist verification:**") or ""
    if alchemist_required:
        run_match = re.match(
            r"^REQUIRED:\s*run_id=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            alchemist_gate,
            re.I,
        )
        if not run_match:
            errors.append(
                "**Alchemist gate:** non-routine semantic work requires REQUIRED run_id=<uuid>"
            )
        else:
            run_id = alchemist_gate.split("=", 1)[1].strip()
            if alchemist_state not in {
                f"alchemist://run/{run_id}/state",
                f"forge://run/{run_id}/state",
            }:
                errors.append(
                    "**Alchemist state reference:** must bind exact required run_id"
                )
        if alchemist_verify != "VERIFIED_NO_CRITICAL_OPEN":
            errors.append(
                "**Alchemist verification:** non-routine semantic work requires VERIFIED_NO_CRITICAL_OPEN"
            )
    else:
        if not (
            re.match(r"^REQUIRED:\s*run_id=", alchemist_gate, re.I)
            or re.match(r"^NOT_REQUIRED:\s*\S", alchemist_gate, re.I)
        ):
            errors.append(
                "**Alchemist gate:** must be REQUIRED run_id=<uuid> or NOT_REQUIRED: <reason>"
            )
        if alchemist_verify not in {"VERIFIED_NO_CRITICAL_OPEN", "NOT_REQUIRED"}:
            errors.append(
                "**Alchemist verification:** must be VERIFIED_NO_CRITICAL_OPEN or NOT_REQUIRED"
            )
        if alchemist_gate.startswith("NOT_REQUIRED:") and alchemist_state != "NOT_REQUIRED":
            errors.append(
                "**Alchemist state reference:** routine NOT_REQUIRED gate requires NOT_REQUIRED"
            )

    def scope_items(value: str, prefix: str) -> list[str]:
        raw = value
        if raw.upper().startswith(prefix):
            raw = raw[len(prefix):]
        return [
            re.sub(r"^(?:and|or)\s+", "", item.strip(), flags=re.I).lower()
            for item in re.split(r"[,|;]", raw)
            if len(item.strip()) >= 4
        ]

    forbidden_raw = label_value(text, "**Explicit forbidden scope:**") or ""
    forbidden_items = scope_items(forbidden_raw, "FORBID:")
    diagnostic_raw = label_value(text, "**Diagnostics only:**") or ""
    diagnostic_items = scope_items(diagnostic_raw, "DIAGNOSTIC_ONLY:")
    ground_truth_raw = label_value(text, "**Ground-truth policy:**") or ""
    measured_raw = (
        ground_truth_raw.split("MEASURED_OUTPUT_NOT_GROUND_TRUTH:", 1)[1]
        if "MEASURED_OUTPUT_NOT_GROUND_TRUTH:" in ground_truth_raw
        else ""
    )
    measured_items = scope_items(measured_raw, "")
    acceptance = table_rows(
        text,
        "## 7. Verification & Acceptance Map",
        "## 8. Evidence & Artifact Contract",
    )
    input_inventory = table_rows(
        text,
        "## 2. Source of Truth & Known State",
        "## 3. Scope & Ownership",
    )
    required_inputs = (label_value(text, "**Required inputs:**") or "").lower()
    acceptance_metrics = (
        label_value(text, "**Acceptance metrics only:**") or ""
    ).lower()
    decision_rule = (label_value(text, "**Decision rule:**") or "").lower()
    acceptance_trace = [
        " | ".join(row).lower()
        for row in table_rows(
            text,
            "### Requirement-to-decision trace",
            "### Model, tool & dependency relevance",
        )[1:]
        if len(row) == 6 and row[1].strip("`") == "ACCEPTANCE"
    ]
    forbidden_targets = "\n".join(
        [" | ".join(row).lower() for row in acceptance[1:]]
        + [" | ".join(row).lower() for row in input_inventory[1:]]
        + acceptance_trace
        + [required_inputs, acceptance_metrics, decision_rule]
    )
    for forbidden_item in forbidden_items:
        if forbidden_item in forbidden_targets:
            errors.append(
                f"forbidden scope leaked into input/acceptance contract: {forbidden_item}"
            )
    diagnostic_targets = "\n".join(
        [" | ".join(row).lower() for row in acceptance[1:]]
        + acceptance_trace
        + [acceptance_metrics, decision_rule]
    )
    for diagnostic_item in diagnostic_items:
        if diagnostic_item in diagnostic_targets:
            errors.append(
                f"diagnostic-only item leaked into acceptance contract: {diagnostic_item}"
            )
    measured_targets = "\n".join(
        [" | ".join(row).lower() for row in input_inventory[1:]]
        + [required_inputs]
    )
    for measured_item in measured_items:
        if measured_item in measured_targets:
            errors.append(
                f"measured output treated as prior input/acceptance requirement: {measured_item}"
            )
    return errors


def authority_correction_errors(text: str, allow_template: bool) -> list[str]:
    if allow_template:
        return []

    errors: list[str] = []
    required_order = (
        "LATEST_USER_INTENT > DECISION_OBJECTIVE > STAGE_CONTRACT > "
        "INHERITED_DOCUMENT > EXISTING_IMPLEMENTATION_OR_PROGRESS"
    )
    authority_order = label_value(text, "**Authority order:**") or ""
    if authority_order.strip().upper() != required_order:
        errors.append(
            "**Authority order:** must be LATEST_USER_INTENT > DECISION_OBJECTIVE > STAGE_CONTRACT > INHERITED_DOCUMENT > EXISTING_IMPLEMENTATION_OR_PROGRESS"
        )

    correction = label_value(text, "**Correction state:**") or ""
    semantic_correction = bool(
        re.match(
            r"^SEMANTIC_CORRECTION:\s*ID:[^;]+;\s*SOURCE:(?:USER_REQUEST|AUTHORITATIVE_SPEC:[^;]+)$",
            correction,
            re.I,
        )
    )
    if not semantic_correction and not re.match(r"^NONE:\s*\S", correction, re.I):
        errors.append(
            "**Correction state:** requires NONE:<reason> or SEMANTIC_CORRECTION: ID:<id>; SOURCE:USER_REQUEST|AUTHORITATIVE_SPEC:<path>"
        )

    correction_audit = label_value(text, "**Correction audit:**") or ""
    correction_audit_match = re.fullmatch(
        r"INVENTORY_SOURCE:([^;]+);\s*SEMANTIC_DELTA:(YES|NO);\s*EVIDENCE:(.+)",
        correction_audit,
        re.I,
    )
    if not correction_audit_match or not PATH_RE.search(
        correction_audit_match.group(3) if correction_audit_match else ""
    ):
        errors.append(
            "**Correction audit:** requires INVENTORY_SOURCE, SEMANTIC_DELTA:YES|NO, & evidence path"
        )
    elif (correction_audit_match.group(2).upper() == "YES") != semantic_correction:
        errors.append(
            "Correction audit semantic delta must match Correction state"
        )

    invalidation = label_value(text, "**Plan invalidation:**") or ""
    if semantic_correction:
        required_tokens = (
            "PLAN_INVALIDATED:ALL",
            "DOWNSTREAM_INVALIDATED_FROM:ROOT",
            "ACTIVE_WORK:STOP_AND_QUARANTINE",
            "LOCAL_PATCH:FORBIDDEN",
        )
        if not all(token in invalidation.upper() for token in required_tokens):
            errors.append(
                "semantic correction requires PLAN_INVALIDATED:ALL, DOWNSTREAM_INVALIDATED_FROM:ROOT, ACTIVE_WORK:STOP_AND_QUARANTINE, & LOCAL_PATCH:FORBIDDEN"
            )
    elif not re.match(
        r"^NOT_APPLICABLE:\s*NO_SEMANTIC_CORRECTION\b",
        invalidation,
        re.I,
    ):
        errors.append(
            "uncorrected dispatch requires Plan invalidation NOT_APPLICABLE:NO_SEMANTIC_CORRECTION"
        )

    rederivation = label_value(text, "**Re-derivation status:**") or ""
    for token in (
        "FROM_ZERO:COMPLETE",
        "OBJECTIVE_RESTATED:COMPLETE",
        "REQUIREMENTS_RECLASSIFIED:COMPLETE",
        "STAGES_REBUILT:COMPLETE",
        "COMMANDS_REBOUND:COMPLETE",
    ):
        if token not in rederivation.upper():
            errors.append(f"Re-derivation status missing {token}")

    progress = label_value(text, "**Progress disposition:**") or ""
    for token in (
        "PRESERVE_EVIDENCE_ONLY",
        "REUSE_ONLY_IF:",
        "STALE_PROGRESS:REJECT",
    ):
        if token not in progress.upper():
            errors.append(f"Progress disposition missing {token}")

    semantics = {
        value.strip().upper()
        for value in re.split(
            r"[\s,|]+",
            label_value(text, "**Task semantics:**") or "",
        )
        if value.strip()
    }
    alchemist_required = bool(
        semantics
        & {
            "EXPERIMENT",
            "BENCHMARK",
            "PERFORMANCE",
            "MODEL",
            "RESEARCH",
            "REPEATED_FAILURE",
        }
    )
    typed_binding = authority_label_value(text, "**Alchemist typed-stage binding:**") or ""
    if alchemist_required:
        match = re.fullmatch(
            r"SCHEMA:dispatch\.stage\.v1;\s*RUN_ID:([0-9a-f-]{36});\s*STATE:(?:alchemist|forge)://run/([0-9a-f-]{36})/state;\s*CHECKPOINT:TYPED_STAGES",
            typed_binding,
            re.I,
        )
        alchemist_gate = authority_label_value(text, "**Alchemist gate:**") or ""
        gate_run = alchemist_gate.split("=", 1)[1].strip() if "=" in alchemist_gate else ""
        if not match or match.group(1).lower() != match.group(2).lower():
            errors.append(
                "non-routine work requires typed Alchemist binding schema, matching run/state IDs, & TYPED_STAGES checkpoint"
            )
        elif match.group(1).lower() != gate_run.lower():
            errors.append(
                "Alchemist typed-stage binding run ID must match Alchemist gate"
            )
    elif not re.match(r"^NOT_REQUIRED:\s*\S", typed_binding, re.I):
        errors.append(
            "routine work requires Alchemist typed-stage binding NOT_REQUIRED:<reason>"
        )

    inherited = table_rows(
        text,
        "### Inherited instruction disposition",
        "## 1C. Goal Route & Critical Path",
    )
    rows = [row for row in inherited[1:] if len(row) == 6]
    clause_ids = [row[0].strip("`") for row in rows]
    if len(clause_ids) != len(set(clause_ids)):
        errors.append("inherited instruction disposition contains duplicate clause IDs")
    allowed_ranks = {
        "LATEST_USER_INTENT",
        "DECISION_OBJECTIVE",
        "STAGE_CONTRACT",
        "INHERITED_DOCUMENT",
        "EXISTING_PROGRESS",
    }
    allowed_compatibility = {"ALIGNED", "CONFLICTS", "NO_DECISION_VALUE"}
    executable_blocks = "\n".join(
        block
        for block in re.findall(r"```[^\n]*\n(.*?)\n```", text, re.S)
        if "STAGE_COMMAND:" in block
    ).casefold()
    active_contract_parts = [
        label_value(text, "**Decision rule:**") or "",
        label_value(text, "**Acceptance metrics only:**") or "",
        label_value(text, "**Required inputs:**") or "",
    ]
    for start, end in (
        ("### Model, tool & dependency relevance", "## 1B. Authority, Correction & Global Re-Derivation"),
        ("### Stage decision funnel", "### Typed stage records"),
        ("### Typed stage records", "### Fixture-stage ownership"),
        ("### Fixture-stage ownership", "### Stage command bindings"),
        ("## 7. Verification & Acceptance Map", "## 8. Evidence & Artifact Contract"),
    ):
        table = table_rows(text, start, end)
        for row in table[1:]:
            if start == "### Typed stage records" and len(row) == 10:
                active_contract_parts.append(" | ".join(row[:7] + row[8:]))
            else:
                active_contract_parts.append(" | ".join(row))
    active_contract_parts.append(executable_blocks)
    active_contract = "\n".join(active_contract_parts).casefold()
    dispositions: list[str] = []
    latest_intent_rows = 0
    for row in rows:
        clause_id = row[0].strip("`")
        source_rank = row[2].strip("`").upper()
        compatibility = row[3].strip("`").upper()
        owner = row[4].strip("`")
        disposition = row[5].strip()
        dispositions.append(disposition)
        if source_rank == "LATEST_USER_INTENT":
            latest_intent_rows += 1
        if source_rank not in allowed_ranks:
            errors.append(
                f"inherited clause {clause_id} has invalid source rank"
            )
        if compatibility not in allowed_compatibility:
            errors.append(
                f"inherited clause {clause_id} has invalid objective compatibility"
            )
        if re.match(r"^KEEP:", disposition, re.I):
            if compatibility != "ALIGNED" or owner == "NONE":
                errors.append(
                    f"inherited clause {clause_id} KEEP requires ALIGNED + stage owner"
                )
            if not re.search(r"\bDECISION_EFFECT:QUESTION_\d+\b", disposition, re.I):
                errors.append(
                    f"inherited clause {clause_id} KEEP lacks numbered decision effect"
                )
        elif re.match(r"^DELETE:", disposition, re.I):
            token_match = re.search(r"\bMATCH_TEXT:([^;]+)", disposition, re.I)
            if owner != "NONE" or compatibility not in {
                "CONFLICTS",
                "NO_DECISION_VALUE",
            }:
                errors.append(
                    f"inherited clause {clause_id} DELETE requires NONE owner + conflict/no-decision-value"
                )
            if not (
                token_match
                and re.search(r"\bEXCLUDE_FROM:[^;]+", disposition, re.I)
                and re.search(r"\bNO_DECISION_EFFECT:\S", disposition, re.I)
            ):
                errors.append(
                    f"inherited clause {clause_id} DELETE lacks MATCH_TEXT, EXCLUDE_FROM, or NO_DECISION_EFFECT"
                )
            elif token_match.group(1).strip().casefold() in active_contract:
                errors.append(
                    f"deleted inherited match text survives active contract: {clause_id}"
                )
        elif re.match(r"^REWRITE:", disposition, re.I):
            if owner == "NONE":
                errors.append(
                    f"inherited clause {clause_id} REWRITE requires stage owner"
                )
            if not (
                (old_match := re.search(r"\bMATCH_TEXT:([^;]+)", disposition, re.I))
                and (new_match := re.search(r"\bREWRITE_TO:([^;]+)", disposition, re.I))
                and re.search(r"\bDECISION_EFFECT:QUESTION_\d+\b", disposition, re.I)
            ):
                errors.append(
                    f"inherited clause {clause_id} REWRITE lacks MATCH_TEXT, REWRITE_TO, or numbered decision effect"
                )
            else:
                if old_match.group(1).strip().casefold() in active_contract:
                    errors.append(
                        f"rewritten inherited match text survives active contract: {clause_id}"
                    )
                if new_match.group(1).strip().casefold() not in active_contract:
                    errors.append(
                        f"rewritten inherited replacement is absent from active contract: {clause_id}"
                    )
        else:
            errors.append(
                f"inherited clause {clause_id} must be KEEP, DELETE, or REWRITE"
            )
        if source_rank == "LATEST_USER_INTENT" and not re.match(
            r"^KEEP:",
            disposition,
            re.I,
        ):
            errors.append("LATEST_USER_INTENT clause cannot be deleted or rewritten")

    if latest_intent_rows < 1:
        errors.append(
            "inherited instruction disposition requires at least one LATEST_USER_INTENT row"
        )
    if semantic_correction and not any(
        re.match(r"^(?:DELETE|REWRITE):", item, re.I)
        for item in dispositions
    ):
        errors.append(
            "semantic correction requires at least one DELETE or REWRITE disposition"
        )

    reconciliation = (
        label_value(text, "**Inherited inventory reconciliation:**") or ""
    )
    reconciliation_match = re.fullmatch(
        r"INVENTORY_TOTAL:(\d+);\s*CLASSIFIED_TOTAL:(\d+);\s*UNCLASSIFIED:(\d+);\s*EVIDENCE:(.+)",
        reconciliation,
        re.I,
    )
    if not reconciliation_match or not PATH_RE.search(
        reconciliation_match.group(4) if reconciliation_match else ""
    ):
        errors.append(
            "**Inherited inventory reconciliation:** requires numeric totals, UNCLASSIFIED:0, & evidence path"
        )
    else:
        inventory_total = int(reconciliation_match.group(1))
        classified_total = int(reconciliation_match.group(2))
        unclassified = int(reconciliation_match.group(3))
        if (
            inventory_total != len(rows)
            or classified_total != len(rows)
            or unclassified != 0
        ):
            errors.append(
                "inherited inventory totals must equal classified rows with UNCLASSIFIED:0"
            )

    return errors


def topology_errors(text: str, allow_template: bool) -> list[str]:
    if allow_template:
        return []

    errors: list[str] = []
    topology = (label_value(text, "**Topology mode:**") or "").strip().upper()
    allowed_topologies = {
        "SELECTION_FUNNEL",
        "FULL_COMPARATIVE_DATASET",
        "SINGLE_PATH",
    }
    if topology not in allowed_topologies:
        errors.append(
            "**Topology mode:** must be SELECTION_FUNNEL, FULL_COMPARATIVE_DATASET, or SINGLE_PATH"
        )

    authorization = label_value(text, "**Full-matrix authorization:**") or ""
    if topology == "FULL_COMPARATIVE_DATASET":
        if not re.match(
            r"^FULL_COMPARATIVE_DATASET_AUTHORIZED:\s*SOURCE:(?:USER_REQUEST|AUTHORITATIVE_SPEC:[^;]+)\s*;\s*REASON:\s*\S",
            authorization,
            re.I,
        ):
            errors.append(
                "full comparative dataset requires FULL_COMPARATIVE_DATASET_AUTHORIZED with SOURCE:USER_REQUEST or SOURCE:AUTHORITATIVE_SPEC:<path> plus REASON"
            )
    elif not re.match(r"^NOT_AUTHORIZED:\s*\S", authorization, re.I):
        errors.append(
            "non-comparative topology requires NOT_AUTHORIZED with exact reason"
        )

    value_rule = label_value(text, "**Value-of-information rule:**") or ""
    if not (
        re.search(r"\bRUN_ONLY_IF:\s*\S", value_rule, re.I)
        and re.search(r"\bSKIP:\s*\S", value_rule, re.I)
    ):
        errors.append(
            "**Value-of-information rule:** requires RUN_ONLY_IF and SKIP decisions"
        )

    ceiling_raw = label_value(text, "**Declared launch ceiling:**") or ""
    ceiling_match = re.fullmatch(r"JOB_TOTAL_MAX:\s*(\d+)", ceiling_raw, re.I)
    declared_total = int(ceiling_match.group(1)) if ceiling_match else None
    if declared_total is None or declared_total < 1:
        errors.append(
            "**Declared launch ceiling:** requires positive JOB_TOTAL_MAX integer"
        )

    wall_total_raw = label_value(text, "**Declared minimum wall time:**") or ""
    wall_total_match = re.fullmatch(
        r"MIN_WALL_MS_TOTAL:\s*(\d+)",
        wall_total_raw,
        re.I,
    )
    declared_wall_total = (
        int(wall_total_match.group(1)) if wall_total_match else None
    )
    if declared_wall_total is None or declared_wall_total < 1:
        errors.append(
            "**Declared minimum wall time:** requires positive MIN_WALL_MS_TOTAL integer"
        )

    estimate_status = label_value(text, "**Launch estimate status:**") or ""
    if estimate_status.upper() != "RESOLVED:RUNS_WALL_TIME_CONCURRENCY":
        errors.append(
            "**Launch estimate status:** must be RESOLVED:RUNS_WALL_TIME_CONCURRENCY"
        )

    reconciliation = label_value(text, "**Launch-count reconciliation:**") or ""
    if not (
        re.search(r"^RECONCILE:", reconciliation, re.I)
        and "STAGE_ACTUAL_SUM" in reconciliation.upper()
        and "JOB_TOTAL_MAX" in reconciliation.upper()
        and "BLOCK_IF_MISMATCH" in reconciliation.upper()
        and PATH_RE.search(reconciliation)
    ):
        errors.append(
            "**Launch-count reconciliation:** requires STAGE_ACTUAL_SUM, JOB_TOTAL_MAX, BLOCK_IF_MISMATCH, & evidence path"
        )

    supervisor = label_value(text, "**Supervisor topology checkpoint:**") or ""
    if not (
        re.search(r"^READBACK_REQUIRED:", supervisor, re.I)
        and re.search(r"\bBEFORE_STAGE:\s*.*\b\d+\b.*\bstage", supervisor, re.I)
        and re.search(r"\b(?:batch|scope change)\b", supervisor, re.I)
    ):
        errors.append(
            "**Supervisor topology checkpoint:** requires readback plus numeric stage cadence before batch/scope change"
        )

    broad_policy = label_value(text, "**Broad selector policy:**") or ""
    if topology == "FULL_COMPARATIVE_DATASET":
        if not re.match(r"^AUTHORIZED_SCOPE:\s*\S", broad_policy, re.I):
            errors.append(
                "full comparative dataset requires AUTHORIZED_SCOPE broad-selector policy"
            )
    elif not re.match(r"^FORBID_BROAD_SELECTORS:\s*\S", broad_policy, re.I):
        errors.append(
            "selection/single topology requires FORBID_BROAD_SELECTORS policy"
        )

    stage_table = table_rows(
        text,
        "### Stage decision funnel",
        "### Typed stage records",
    )
    stage_rows = [row for row in stage_table[1:] if len(row) == 10]
    stage_ids = [row[0].strip("`") for row in stage_rows]
    if len(stage_ids) != len(set(stage_ids)):
        errors.append("stage decision funnel contains duplicate stage IDs")

    expected_gate_types = {
        "TECHNICAL_RUNNABILITY": "TECHNICAL",
        "BEHAVIORAL_UTILITY": "BEHAVIORAL",
        "PERFORMANCE_SHORTLIST": "PERFORMANCE",
        "SAFETY_NEGATIVES": "SAFETY_VALIDATION",
        "SYSTEM_INTERFERENCE": "SYSTEM_INTERFERENCE",
        "FULL_COMPARATIVE_MATRIX": "FULL_MATRIX",
        "SINGLE_PATH_EXECUTION": "SINGLE_PATH",
    }
    stage_data: dict[str, dict[str, object]] = {}
    stage_job_sum = 0
    for row in stage_rows:
        stage_id = row[0].strip("`")
        gate_type = row[1].strip("`").upper()
        expected_gate = expected_gate_types.get(stage_id)
        if expected_gate and gate_type != expected_gate:
            errors.append(
                f"stage {stage_id} gate type must be {expected_gate}"
            )
        if "QUESTION_" not in row[2].upper():
            errors.append(f"stage {stage_id} lacks numbered decision question")

        input_match = re.search(r"\bMAX_INPUTS:\s*(\d+)", row[3], re.I)
        max_inputs = int(input_match.group(1)) if input_match else None
        if max_inputs is None or max_inputs < 1:
            errors.append(f"stage {stage_id} requires positive MAX_INPUTS")

        workload_match = re.search(
            r"\bFACTORS:\s*(\d+(?:\s*[xX]\s*\d+)+)\s*;\s*MAX_JOBS:\s*(\d+)\s*;\s*ACTUAL_COUNT:\s*([^;]+)",
            row[5],
            re.I,
        )
        max_jobs = None
        workload_actual_path = ""
        if not workload_match:
            errors.append(
                f"stage {stage_id} workload requires FACTORS, MAX_JOBS, & ACTUAL_COUNT path"
            )
        else:
            factors = [
                int(value)
                for value in re.split(r"\s*[xX]\s*", workload_match.group(1))
            ]
            max_jobs = int(workload_match.group(2))
            workload_actual_path = workload_match.group(3).strip().strip("`")
            product = 1
            for factor in factors:
                product *= factor
            if product != max_jobs:
                errors.append(
                    f"stage {stage_id} MAX_JOBS does not equal factor product"
                )
            if max_inputs is not None and factors[0] != max_inputs:
                errors.append(
                    f"stage {stage_id} first workload factor must equal MAX_INPUTS"
                )
            if not PATH_RE.search(workload_actual_path):
                errors.append(f"stage {stage_id} ACTUAL_COUNT lacks path")
            stage_job_sum += max_jobs

        selector = row[6]
        if not re.match(r"^SELECTOR:\s*\S", selector, re.I):
            errors.append(f"stage {stage_id} requires exact SELECTOR")
        if not re.match(r"^PASS_IF:\s*\S", row[7], re.I):
            errors.append(f"stage {stage_id} requires PASS_IF exit gate")

        survivor_match = re.search(
            r"\bSURVIVORS:\s*([^;]+)\s*;\s*ACTUAL_COUNT:\s*([^;]+)",
            row[8],
            re.I,
        )
        survivor_path = ""
        survivor_actual_path = ""
        if not survivor_match:
            errors.append(
                f"stage {stage_id} requires SURVIVORS & ACTUAL_COUNT paths"
            )
        else:
            survivor_path = survivor_match.group(1).strip().strip("`")
            survivor_actual_path = survivor_match.group(2).strip().strip("`")
            if not PATH_RE.search(survivor_path):
                errors.append(f"stage {stage_id} survivor artifact lacks path")
            if not PATH_RE.search(survivor_actual_path):
                errors.append(
                    f"stage {stage_id} survivor ACTUAL_COUNT lacks path"
                )
            if (
                workload_actual_path
                and normalized_path(workload_actual_path)
                != normalized_path(survivor_actual_path)
            ):
                errors.append(
                    f"stage {stage_id} actual-count ledger paths do not match"
                )

        stage_data[stage_id] = {
            "row": row,
            "max_inputs": max_inputs,
            "max_jobs": max_jobs,
            "survivor_path": survivor_path,
            "actual_path": survivor_actual_path,
            "selector": selector,
        }

    typed_table = table_rows(
        text,
        "### Typed stage records",
        "### Fixture-stage ownership",
    )
    typed_rows = [row for row in typed_table[1:] if len(row) == 10]
    typed_ids = [row[0].strip("`") for row in typed_rows]
    if typed_ids != stage_ids:
        errors.append(
            "typed stage records must match stage decision funnel IDs and order"
        )
    typed_data: dict[str, dict[str, object]] = {}
    stage_wall_sum = 0
    for row in typed_rows:
        stage_id = row[0].strip("`")
        decision = row[1]
        question_match = re.search(r"\bQUESTION_\d+\b", decision, re.I)
        if not question_match:
            errors.append(f"typed stage {stage_id} lacks numbered decision")

        provider = row[2].strip()
        provider_match = re.match(
            r"^PROVIDER:([^;]+);\s*REQUIRED_FOR:(QUESTION_\d+):(\S.+)$",
            provider,
            re.I,
        )
        no_provider = re.match(
            r"^NO_PROVIDER:(QUESTION_\d+)\s+\S",
            provider,
            re.I,
        )
        provider_name = ""
        provider_question = ""
        if provider_match:
            provider_name = provider_match.group(1).strip()
            provider_question = provider_match.group(2).upper()
        elif no_provider:
            provider_question = no_provider.group(1).upper()
        else:
            errors.append(
                f"typed stage {stage_id} provider must bind PROVIDER + REQUIRED_FOR or NO_PROVIDER + question"
            )
        if (
            question_match
            and provider_question
            and provider_question != question_match.group(0).upper()
        ):
            errors.append(
                f"typed stage {stage_id} provider justification targets wrong question"
            )

        dataset = row[3].strip()
        if not re.match(r"^DATASET:\S.+;\s*ROLE:\S", dataset, re.I):
            errors.append(
                f"typed stage {stage_id} dataset requires DATASET + ROLE"
            )

        mode_match = re.match(r"^MODE:([A-Z][A-Z0-9_]*)$", row[4].strip(), re.I)
        mode = mode_match.group(1).upper() if mode_match else ""
        if not mode:
            errors.append(f"typed stage {stage_id} requires exact MODE")
        if not re.match(r"^ADMIT_IF:\S", row[5], re.I):
            errors.append(f"typed stage {stage_id} requires ADMIT_IF")
        if not re.match(r"^PASS_IF:\S", row[6], re.I):
            errors.append(f"typed stage {stage_id} requires PASS_IF")
        if not re.match(r"^EXCLUDE:\S", row[7], re.I):
            errors.append(f"typed stage {stage_id} requires explicit EXCLUDE")

        runs_match = re.fullmatch(r"ESTIMATED_RUNS:(\d+)", row[8].strip(), re.I)
        estimated_runs = int(runs_match.group(1)) if runs_match else None
        if estimated_runs is None or estimated_runs < 1:
            errors.append(
                f"typed stage {stage_id} requires positive ESTIMATED_RUNS"
            )

        wall_match = re.fullmatch(
            r"WALL_FACTORS:RUNS=(\d+);\s*MS_PER_RUN_MIN=(\d+);\s*MAX_CONCURRENCY=(\d+);\s*MIN_WALL_MS=(\d+)(?:;\s*EVIDENCE:(.+))?",
            row[9].strip(),
            re.I,
        )
        min_wall_ms = None
        if not wall_match:
            errors.append(
                f"typed stage {stage_id} requires integer WALL_FACTORS"
            )
        else:
            wall_runs = int(wall_match.group(1))
            ms_per_run = int(wall_match.group(2))
            concurrency = int(wall_match.group(3))
            min_wall_ms = int(wall_match.group(4))
            wall_evidence = wall_match.group(5) or ""
            if concurrency < 1 or ms_per_run < 1:
                errors.append(
                    f"typed stage {stage_id} wall factors require positive duration + concurrency"
                )
            else:
                computed = (wall_runs * ms_per_run + concurrency - 1) // concurrency
                if min_wall_ms != computed:
                    errors.append(
                        f"typed stage {stage_id} MIN_WALL_MS does not equal expanded wall-time formula"
                    )
            if estimated_runs is not None and wall_runs != estimated_runs:
                errors.append(
                    f"typed stage {stage_id} wall RUNS must equal ESTIMATED_RUNS"
                )
            if not PATH_RE.search(wall_evidence):
                errors.append(
                    f"typed stage {stage_id} wall factors require evidence path"
                )
            stage_wall_sum += min_wall_ms

        stage = stage_data.get(stage_id, {})
        max_jobs = stage.get("max_jobs")
        if isinstance(max_jobs, int) and estimated_runs != max_jobs:
            errors.append(
                f"typed stage {stage_id} ESTIMATED_RUNS must equal stage MAX_JOBS"
            )
        stage_decision = str(stage.get("row", ["", "", ""])[2]) if stage else ""
        stage_question = re.search(r"\bQUESTION_\d+\b", stage_decision, re.I)
        if (
            question_match
            and stage_question
            and question_match.group(0).upper()
            != stage_question.group(0).upper()
        ):
            errors.append(
                f"typed stage {stage_id} decision does not match funnel question"
            )
        if stage and decision.strip().casefold() != stage_decision.strip().casefold():
            errors.append(
                f"typed stage {stage_id} decision text differs from funnel decision"
            )
        if stage:
            typed_pass = re.sub(r"^PASS_IF:\s*", "", row[6], flags=re.I).strip()
            funnel_pass = re.sub(
                r"^PASS_IF:\s*",
                "",
                str(stage["row"][7]),
                flags=re.I,
            ).strip()
            if typed_pass.casefold() != funnel_pass.casefold():
                errors.append(
                    f"typed stage {stage_id} pass rule differs from funnel exit gate"
                )

        typed_data[stage_id] = {
            "provider_name": provider_name,
            "dataset": dataset,
            "mode": mode,
            "estimated_runs": estimated_runs,
            "min_wall_ms": min_wall_ms,
        }

    if declared_total is not None and stage_job_sum != declared_total:
        errors.append(
            f"JOB_TOTAL_MAX {declared_total} does not equal stage MAX_JOBS sum {stage_job_sum}"
        )
    if declared_wall_total is not None and stage_wall_sum != declared_wall_total:
        errors.append(
            f"MIN_WALL_MS_TOTAL {declared_wall_total} does not equal typed stage wall sum {stage_wall_sum}"
        )

    if topology == "SELECTION_FUNNEL":
        required_order = [
            "TECHNICAL_RUNNABILITY",
            "BEHAVIORAL_UTILITY",
            "PERFORMANCE_SHORTLIST",
            "SAFETY_NEGATIVES",
            "SYSTEM_INTERFERENCE",
        ]
        if stage_ids != required_order:
            errors.append(
                "selection funnel requires exact ordered stages: "
                + " -> ".join(required_order)
            )
        for index, stage_id in enumerate(required_order):
            current = stage_data.get(stage_id)
            if current is None:
                continue
            row = current["row"]
            selector_text = str(current["selector"])
            if re.search(r"(?<![\w-])--all(?:\s|$)", selector_text, re.I):
                errors.append(
                    f"stage {stage_id} selector contains forbidden broad --all"
                )
            if re.search(
                r"--candidates?(?:-from)?\s+[\"']?\*|--corpus\s+(?:all|full)\b",
                selector_text,
                re.I,
            ):
                errors.append(
                    f"stage {stage_id} selector contains wildcard/full-corpus scope"
                )
            if index == 0:
                if not re.search(r"\bALL_CANDIDATES\b", row[3], re.I):
                    errors.append(
                        "TECHNICAL_RUNNABILITY input must be ALL_CANDIDATES"
                    )
                if not re.match(r"^START:\s*\S", row[4], re.I):
                    errors.append(
                        "TECHNICAL_RUNNABILITY entry gate must be START"
                    )
            else:
                prior_id = required_order[index - 1]
                prior = stage_data.get(prior_id)
                expected_source = f"SURVIVORS_FROM:{prior_id}"
                if expected_source not in row[3].upper():
                    errors.append(
                        f"stage {stage_id} must consume {expected_source}"
                    )
                if not re.match(
                    rf"^PASS_FROM:{re.escape(prior_id)}\b",
                    row[4],
                    re.I,
                ):
                    errors.append(
                        f"stage {stage_id} entry gate must PASS_FROM:{prior_id}"
                    )
                prior_path = str(prior["survivor_path"]) if prior else ""
                prior_key = prior_path.replace("\\", "/").casefold()
                selector_key = str(current["selector"]).replace("\\", "/").casefold()
                if prior_key and prior_key not in selector_key:
                    errors.append(
                        f"stage {stage_id} selector must use upstream survivor artifact"
                    )
                prior_max = prior.get("max_inputs") if prior else None
                current_max = current.get("max_inputs")
                if (
                    isinstance(prior_max, int)
                    and isinstance(current_max, int)
                    and current_max > prior_max
                ):
                    errors.append(
                        f"stage {stage_id} MAX_INPUTS exceeds upstream population"
                    )

            if index < len(required_order) - 1:
                expected_prohibition = f"PROHIBITED_UNTIL:{stage_id}:PASS"
                if expected_prohibition not in row[9].upper():
                    errors.append(
                        f"stage {stage_id} downstream gate must be {expected_prohibition}"
                    )
            elif not re.match(r"^TERMINAL:\s*\S", row[9], re.I):
                errors.append(
                    "SYSTEM_INTERFERENCE downstream state must be TERMINAL"
                )

        fenced = "\n".join(
            re.findall(r"```[^\n]*\n(.*?)\n```", text, re.S)
        )
        if re.search(r"(?<![\w-])--all(?:\s|$)", fenced, re.I):
            errors.append(
                "selection funnel command contains forbidden broad --all selector"
            )
        if re.search(
            r"--candidates?(?:-from)?\s+[\"']?\*|--corpus\s+(?:all|full)\b",
            fenced,
            re.I,
        ):
            errors.append(
                "selection funnel command contains wildcard/full-corpus selector"
            )
    elif topology == "FULL_COMPARATIVE_DATASET":
        if stage_ids != ["FULL_COMPARATIVE_MATRIX"]:
            errors.append(
                "full comparative dataset requires one FULL_COMPARATIVE_MATRIX stage"
            )
    elif topology == "SINGLE_PATH":
        if stage_ids != ["SINGLE_PATH_EXECUTION"]:
            errors.append(
                "single-path topology requires one SINGLE_PATH_EXECUTION stage"
            )

    requirement_trace = table_rows(
        text,
        "### Requirement-to-decision trace",
        "### Model, tool & dependency relevance",
    )
    for row in requirement_trace[1:]:
        if len(row) != 6:
            continue
        requirement_id = row[0].strip("`")
        requirement_class = row[1].strip("`")
        owner = row[3].strip("`")
        if requirement_class in {"ACCEPTANCE", "EXECUTION_INPUT"}:
            if owner not in stage_ids:
                errors.append(
                    f"requirement {requirement_id} lacks declared stage owner"
                )
        elif owner != "NONE" and owner not in stage_ids:
            errors.append(
                f"requirement {requirement_id} has invalid stage owner"
            )

    inherited_table = table_rows(
        text,
        "### Inherited instruction disposition",
        "## 1C. Goal Route & Critical Path",
    )
    for row in inherited_table[1:]:
        if len(row) != 6:
            continue
        clause_id = row[0].strip("`")
        owner = row[4].strip("`")
        if owner != "NONE" and owner not in stage_ids:
            errors.append(
                f"inherited clause {clause_id} has undeclared stage owner"
            )

    fixture_table = table_rows(
        text,
        "### Fixture-stage ownership",
        "### Stage command bindings",
    )
    fixture_rows = [row for row in fixture_table[1:] if len(row) == 7]
    fixture_ids = [row[0].strip("`") for row in fixture_rows]
    if len(fixture_ids) != len(set(fixture_ids)):
        errors.append("fixture-stage ownership contains duplicate fixture IDs")
    for row in fixture_rows:
        fixture_id = row[0].strip("`")
        owner = row[2].strip("`")
        if owner not in stage_ids:
            errors.append(
                f"fixture {fixture_id} owner is not a declared stage: {owner}"
            )
        if not (PATH_RE.search(row[1]) or re.match(r"^[A-Za-z0-9_.:-]{4,}$", row[1])):
            errors.append(f"fixture {fixture_id} lacks exact source")
        if not re.match(
            rf"^RUN_ONLY_IF:{re.escape(owner)}:ENTRY_PASS\b",
            row[5],
            re.I,
        ):
            errors.append(
                f"fixture {fixture_id} use condition must bind owning stage entry"
            )
        if not re.match(r"^(?:FORBID:|NONE_AUTHORIZED:)\s*\S", row[6], re.I):
            errors.append(
                f"fixture {fixture_id} requires forbidden-outside scope"
            )

    command_blocks: dict[str, list[str]] = {}
    for block in re.findall(r"```[^\n]*\n(.*?)\n```", text, re.S):
        tag = re.search(
            r"(?mi)^\s*#\s*STAGE_COMMAND:\s*([A-Z][A-Z0-9_]*)\s*$",
            block,
        )
        if tag:
            command_blocks.setdefault(tag.group(1).upper(), []).append(block)

    for stage_id in stage_ids:
        blocks = command_blocks.get(stage_id, [])
        if len(blocks) != 1:
            errors.append(
                f"stage {stage_id} requires exactly one STAGE_COMMAND block"
            )
            continue
        block_key = blocks[0].replace("\\", "/").casefold()
        stage = stage_data.get(stage_id, {})
        for field, label in (
            ("survivor_path", "survivor artifact"),
            ("actual_path", "actual-count ledger"),
        ):
            expected = str(stage.get(field, "")).replace("\\", "/").casefold()
            if expected and expected not in block_key:
                errors.append(
                    f"stage {stage_id} command lacks declared {label} path"
                )
        typed = typed_data.get(stage_id, {})
        provider_name = str(typed.get("provider_name", "")).casefold()
        if provider_name and provider_name not in block_key:
            errors.append(
                f"stage {stage_id} command lacks required provider binding"
            )
        mode = str(typed.get("mode", ""))
        if mode and mode.casefold() not in block_key:
            errors.append(
                f"stage {stage_id} command lacks declared execution mode"
            )
        if mode == "OFFLINE_LOGICAL_CHUNKS" and re.search(
            r"(?im)\bStart-Sleep\b|(?:^|\s)sleep(?:\.exe)?(?:\s|$)|\btime\.sleep\s*\(|\bThread\.Sleep\s*\(|\bTask\.Delay\s*\(|\btimeout(?:\.exe)?\s+/t\b|\bWait-Event\b|--(?:real-?time|wall-clock)\b",
            blocks[0],
        ):
            errors.append(
                f"offline stage {stage_id} command contains physical sleep/realtime pacing"
            )

    if topology == "SELECTION_FUNNEL":
        for index, stage_id in enumerate(stage_ids):
            blocks = command_blocks.get(stage_id, [])
            if len(blocks) != 1:
                continue
            block_key = blocks[0].replace("\\", "/").casefold()
            if index > 0:
                prior = stage_data.get(stage_ids[index - 1], {})
                prior_path = (
                    str(prior.get("survivor_path", ""))
                    .replace("\\", "/")
                    .casefold()
                )
                if prior_path and prior_path not in block_key:
                    errors.append(
                        f"stage {stage_id} command does not consume upstream survivor artifact"
                    )
            if re.search(r"(?<![\w-])--all(?:\s|$)", blocks[0], re.I):
                errors.append(
                    f"stage {stage_id} command contains forbidden broad --all selector"
                )
            if re.search(
                r"--candidates?(?:-from)?\s+[\"']?\*|--corpus\s+(?:all|full)\b",
                blocks[0],
                re.I,
            ):
                errors.append(
                    f"stage {stage_id} command contains wildcard/full-corpus selector"
                )

    for row in fixture_rows:
        fixture_id = row[0].strip("`")
        source = row[1].strip("`")
        owner = row[2].strip("`")
        blocks = command_blocks.get(owner, [])
        if len(blocks) == 1:
            block_key = blocks[0].replace("\\", "/").casefold()
            source_key = source.replace("\\", "/").casefold()
            if source_key not in block_key:
                errors.append(
                    f"fixture {fixture_id} source is absent from owning stage command"
                )
            typed_dataset = str(
                typed_data.get(owner, {}).get("dataset", "")
            ).replace("\\", "/").casefold()
            if source_key not in typed_dataset:
                errors.append(
                    f"fixture {fixture_id} source is absent from owning typed stage dataset"
                )
        source_key = source.replace("\\", "/").casefold()
        for other_stage, other_blocks in command_blocks.items():
            if other_stage == owner or len(other_blocks) != 1:
                continue
            other_key = other_blocks[0].replace("\\", "/").casefold()
            if source_key in other_key:
                errors.append(
                    f"fixture {fixture_id} leaks into non-owning stage command {other_stage}"
                )

    return errors


def validate(
    text: str, allow_template: bool = False, artifact_path: Path | None = None
) -> list[str]:
    errors = ordered_heading_errors(text)

    for label in REQUIRED_LABELS:
        value = authority_label_value(text, label)
        if value is None:
            errors.append(f"missing label: {label}")
        elif not value and label not in {
            "**Preflight command:**",
            "**Final verification command:**",
            "**Validator command:**",
            "**Receiver hash check:**",
            "**Lifecycle preflight:**",
            "**Environment integrity step zero:**",
            "**Canary / one-unit preflight:**",
        }:
            errors.append(f"empty value: {label}")
        elif not allow_template and value.strip().strip("`").lower() in GENERIC_VALUES:
            errors.append(f"generic filler value: {label}")

    if not allow_template:
        for label in ("**Preflight command:**", "**Final verification command:**"):
            command = fenced_value_after(text, label)
            if command is None or not is_concrete(command) or not ACTION_RE.search(command):
                errors.append(f"{label} lacks executable fenced command/action")
        validator_command = fenced_value_after(text, "**Validator command:**") or ""
        receiver_command = fenced_value_after(text, "**Receiver hash check:**") or ""
        declared_artifact = clean_path_value(
            label_value(text, "**Validated artifact path:**") or ""
        )
        declared_receipt = clean_path_value(label_value(text, "**Receipt path:**") or "")
        for label, command, flag in (
            ("Validator command", validator_command, "--write-receipt"),
            ("Receiver hash check", receiver_command, "--verify-receipt"),
        ):
            normalized_command = command.replace("\\", "/").casefold()
            artifact_token = declared_artifact.replace("\\", "/").casefold()
            receipt_token = declared_receipt.replace("\\", "/").casefold()
            if (
                "validate-dispatch.py" not in command
                or flag not in command
                or artifact_token not in normalized_command
                or receipt_token not in normalized_command
            ):
                errors.append(
                    f"{label} must execute validate-dispatch.py with bound paths and {flag}"
                )
        root_cwd = label_value(text, "**Working directory:**") or ""
        if not PATH_RE.search(root_cwd):
            errors.append("dispatch working directory is not an explicit path")

        # Must run before receipt generation binds this dispatch's executable text.
        errors.extend(managed_rust_route_errors(text, artifact_path))

    errors.extend(step_errors(text, allow_template))
    errors.extend(table_errors(text, allow_template))
    errors.extend(execution_identity_errors(text, allow_template))
    errors.extend(execution_control_errors(text, allow_template))
    errors.extend(decision_scope_errors(text, allow_template))
    errors.extend(authority_correction_errors(text, allow_template))
    errors.extend(goal_route_errors(text, allow_template, artifact_path))
    errors.extend(topology_errors(text, allow_template))

    for failure_class in FAILURE_CLASSES:
        if text.count(failure_class) < 1:
            errors.append(f"missing failure class: {failure_class}")

    script_involved = label_value(text, "**Script involved:**")
    if script_involved and not allow_template:
        normalized = script_involved.strip("`").upper()
        if normalized not in {"YES", "NO"}:
            errors.append("Script involved must be exactly YES or NO")
        ownership = (label_value(text, "**Script ownership:**") or "").strip("`").upper()
        script_path = label_value(text, "**Script path:**") or ""
        no_reason = label_value(text, "**No-script reason:**") or ""
        gate = script_gate_values(text)
        if normalized == "YES":
            script_skill = label_value(text, "**Script skill:**") or ""
            if "/script/skill.md" not in script_skill.replace("\\", "/").lower():
                errors.append("script-bearing dispatch must name /script skill path")
            if ownership not in {"ORCHESTRATOR_CREATED", "EXISTING_VERIFIED", "EXECUTOR_CREATES"}:
                errors.append("script-bearing dispatch must name script owner")
            if not PATH_RE.search(script_path):
                errors.append("script-bearing dispatch must name explicit script path")
            if not no_reason.upper().startswith("NOT_APPLICABLE"):
                errors.append("script-bearing dispatch must mark no-script reason NOT_APPLICABLE")
            if gate.get("TIER") not in {"S1", "S2", "S3"}:
                errors.append("script-bearing dispatch requires TIER S1, S2, or S3")
            for marker in (
                "GOAL",
                "SELECTED_PATH",
                "WHY_FASTEST_VALID",
                "BOTTLENECK",
                "PARALLEL",
                "DEFERRED",
                "GOAL_ROUTE_ARTIFACT",
                "GOAL_ROUTE_RECEIPT",
                "EXPECTED_TIME_TO_VERIFIED_B_MS",
                "ROUTE_REVISION",
                "PRE",
                "SMOKE",
                "CHECK",
                "BLAST",
                "OPT",
            ):
                value = gate.get(marker, "")
                if marker in {
                    "EXPECTED_TIME_TO_VERIFIED_B_MS",
                    "ROUTE_REVISION",
                }:
                    if not re.fullmatch(r"[1-9]\d*|0", value):
                        errors.append(f"script gate {marker} requires integer")
                elif not is_concrete(value):
                    errors.append(f"script gate {marker} lacks concrete evidence")
            selected_route = re.sub(
                r"^SELECTED_ROUTE:\s*",
                "",
                label_value(text, "**Selected route:**") or "",
                flags=re.I,
            ).strip("` ")
            if selected_route.casefold() not in gate.get(
                "SELECTED_PATH", ""
            ).casefold():
                errors.append("script gate SELECTED_PATH must bind dispatch selected route")
            route_artifact = clean_path_value(
                label_value(text, "**Goal route artifact:**") or ""
            )
            route_receipt = clean_path_value(
                label_value(text, "**Goal route receipt:**") or ""
            )
            expected_time = re.sub(
                r"^EXPECTED_TIME_TO_VERIFIED_B_MS:",
                "",
                label_value(text, "**Expected time to verified B:**") or "",
                flags=re.I,
            )
            route_revision = re.sub(
                r"^ROUTE_REVISION:",
                "",
                label_value(text, "**Route revision:**") or "",
                flags=re.I,
            )
            if normalized_path(gate.get("GOAL_ROUTE_ARTIFACT", "")) != normalized_path(
                route_artifact
            ):
                errors.append("script gate GOAL_ROUTE_ARTIFACT must bind dispatch route")
            if normalized_path(gate.get("GOAL_ROUTE_RECEIPT", "")) != normalized_path(
                route_receipt
            ):
                errors.append("script gate GOAL_ROUTE_RECEIPT must bind dispatch receipt")
            if gate.get("EXPECTED_TIME_TO_VERIFIED_B_MS") != expected_time:
                errors.append(
                    "script gate EXPECTED_TIME_TO_VERIFIED_B_MS must match dispatch route"
                )
            if gate.get("ROUTE_REVISION") != route_revision:
                errors.append("script gate ROUTE_REVISION must match dispatch route")
            expected_ship = "EXECUTOR_MUST_EARN" if ownership == "EXECUTOR_CREATES" else "YES"
            if gate.get("SHIP") != expected_ship:
                errors.append(f"script gate SHIP must be {expected_ship} for {ownership}")
        elif normalized == "NO":
            if not is_concrete(no_reason):
                errors.append("Script involved NO requires explicit reason")
            if ownership != "NOT_APPLICABLE":
                errors.append("Script involved NO requires NOT_APPLICABLE ownership")
            execution = text[text.find("## 5. Execution Procedure"):text.find("## 5A. Script & Runner Gate")]
            if re.search(r"\b(script|runner|pipeline|batch|deploy|render|install|paid API|production)\b", execution, re.I):
                errors.append("script-bearing execution cannot declare Script involved NO")

    for marker in (
        "GOAL:",
        "SELECTED_PATH:",
        "WHY_FASTEST_VALID:",
        "BOTTLENECK:",
        "PARALLEL:",
        "DEFERRED:",
        "GOAL_ROUTE_ARTIFACT:",
        "GOAL_ROUTE_RECEIPT:",
        "EXPECTED_TIME_TO_VERIFIED_B_MS:",
        "ROUTE_REVISION:",
        "TIER:",
        "PRE:",
        "SMOKE:",
        "CHECK:",
        "BLAST:",
        "OPT:",
        "SHIP:",
    ):
        if marker not in text:
            errors.append(f"missing /script gate marker: {marker}")

    errors.extend(status_errors(text))
    for status in ("COMPLETE", "COMPLETE_WITH_NOTES", "TRUE_BLOCKER"):
        if status not in text:
            errors.append(f"missing terminal status contract: {status}")

    if text.count("```") < 8:
        errors.append("expected at least four fenced command/output blocks")

    blocker_section = text[
        text.find("## 10. TRUE_BLOCKER Conditions"):text.find(
            "## 11. Dispatcher Author Gate"
        )
    ]
    for token in (
        "RECOVERY_EXHAUSTED",
        "INDEPENDENT_WORK_COMPLETE",
        "RAW_EVIDENCE",
        "MISSING_INPUT",
        "RESUME_COMMAND",
    ):
        if token not in blocker_section:
            errors.append(f"TRUE_BLOCKER section missing proof token: {token}")

    author_section = text[text.find("## 11. Dispatcher Author Gate"):]
    if not allow_template:
        if PLACEHOLDER_RE.search(text):
            errors.append("unfilled placeholder remains")
        if "- [ ]" in author_section:
            errors.append("dispatcher author gate contains unchecked item")
        if author_section.count("- [x]") < 15:
            errors.append("dispatcher author gate requires 15 checked items")

    for name, pattern in BYPASS_PATTERNS.items():
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            errors.append(f"{name}: forbidden phrase '{match.group(0)}'")
    if not allow_template:
        for name, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, text):
                errors.append(f"possible secret detected: {name}")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dispatch", type=Path)
    parser.add_argument("--packet-type", choices=("authority", "worker", "legacy"), default="legacy")
    parser.add_argument(
        "--template-self-check",
        action="store_true",
        help="allow template placeholders and unchecked author-gate boxes",
    )
    receipt_group = parser.add_mutually_exclusive_group()
    receipt_group.add_argument("--write-receipt", type=Path)
    receipt_group.add_argument("--verify-receipt", type=Path)
    args = parser.parse_args()

    if not args.dispatch.is_file():
        print(f"FAIL: dispatch file not found: {args.dispatch}", file=sys.stderr)
        return 2
    if (
        not args.template_self_check
        and args.write_receipt is None
        and args.verify_receipt is None
    ):
        print("FAIL: exactly one receipt mode is required")
        return 1

    raw_bytes = args.dispatch.read_bytes()
    if args.packet_type in {"authority", "worker"}:
        try:
            packet = json.loads(raw_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            print(f"FAIL: authority packet is not valid JSON: {exc}")
            return 1
        if args.packet_type == "worker" and packet.get("packetType") != "worker":
            print("FAIL: worker mode requires worker packet")
            return 1
        errors, references = authority_packet_errors(packet, args.dispatch.resolve())
        if errors:
            print(f"FAIL: {len(errors)} authority dispatch defect(s)")
            for error in errors: print(f"- {error}")
            return 1
        digest = hashlib.sha256(raw_bytes).hexdigest()
        authority_binding = {
            "packet_sha256": digest,
            "source_revision": packet["sourceRevision"],
            "prompt_digest": packet["promptDigest"],
        }
        if args.verify_receipt:
            try: receipt = json.loads(args.verify_receipt.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc: print(f"FAIL: invalid receipt: {exc}"); return 1
            if (
                receipt.get("sha256") != digest
                or receipt.get("referenced_artifacts") != references
                or receipt.get("authority_binding") != authority_binding
            ):
                print("FAIL: packet, source/prompt binding, or referenced artifacts do not match receipt"); return 1
        if args.write_receipt:
            args.write_receipt.write_text(json.dumps({"schema_version": 4, "sha256": digest, "referenced_artifacts": references, "authority_binding": authority_binding}, indent=2) + "\n", encoding="utf-8")
        print(f"PASS: {args.packet_type} packet is structurally complete (sha256={digest})")
        return 0
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        print(f"FAIL: dispatch is not valid UTF-8: {exc}")
        return 1
    errors = validate(
        text,
        allow_template=args.template_self_check,
        artifact_path=args.dispatch.resolve(),
    )
    if not args.template_self_check:
        minimize_path = args.dispatch.with_suffix(".minimize.json")
        minimize_receipt = args.dispatch.with_suffix(".minimize.receipt.json")
        try:
            minimize_validator_path = (
                Path(__file__).resolve().parents[1]
                / "minimize"
                / "minimize_gate.py"
            )
            spec = importlib.util.spec_from_file_location(
                "dispatch_minimize_validator", minimize_validator_path
            )
            if spec is None or spec.loader is None:
                raise RuntimeError("cannot load Minimize validator")
            minimize = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(minimize)
            minimize.verify_decision(minimize_path, minimize_receipt)
        except (OSError, ValueError, RuntimeError) as exc:
            errors.append(f"Minimize authority missing, invalid, or stale: {exc}")
        errors.extend(
            storage_errors(
                text, args.dispatch, args.write_receipt, args.verify_receipt
            )
        )
    if errors:
        print(f"FAIL: {len(errors)} dispatch defect(s)")
        for error in errors:
            print(f"- {error}")
        return 1

    digest = hashlib.sha256(raw_bytes).hexdigest()
    if args.verify_receipt:
        if not args.verify_receipt.is_file():
            print(f"FAIL: receipt file not found: {args.verify_receipt}")
            return 2
        try:
            receipt = json.loads(args.verify_receipt.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"FAIL: invalid receipt: {exc}")
            return 1
        if receipt.get("sha256") != digest:
            print("FAIL: dispatch bytes do not match receipt")
            return 1
        if receipt.get("artifact_name") != args.dispatch.name:
            print("FAIL: dispatch filename does not match receipt")
            return 1
        if receipt.get("artifact_path") != canonical_locator(args.dispatch):
            print("FAIL: dispatch path does not match receipt")
            return 1
        print(f"RECEIPT_PASS: sha256={digest}")
    if args.write_receipt:
        receipt = {
            "schema_version": 2,
            "artifact_name": args.dispatch.name,
            "artifact_path": canonical_locator(args.dispatch),
            "sha256": digest,
            "validated_at": datetime.now(timezone.utc).isoformat(),
            "validator": "dispatch/validate-dispatch.py",
        }
        args.write_receipt.parent.mkdir(parents=True, exist_ok=True)
        args.write_receipt.write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
    print(
        "PASS: dispatch is structurally complete "
        f"({len(STEP_RE.findall(text))} step(s), {len(FAILURE_CLASSES)} failure classes, "
        f"sha256={digest})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
