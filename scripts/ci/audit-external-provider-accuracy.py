#!/usr/bin/env python3
"""Strictly validate the native real-ShellCheck benchmark receipt."""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath


PROVIDER = "security.scanner-shellcheck"
POLICY = "legion-real-shellcheck-benchmark-v1"
HARNESS = "engine/crates/legion-audit/tests/external_scanner_accuracy.rs"
TOOL_ARGS = ["--norc", "-f", "json", "--severity=style", "--", "./src/check.sh"]
IMPL_TREES = [
    "engine/crates/legion-audit/src",
    "engine/crates/legion-effects/src",
    "engine/crates/legion-provider-sdk/src",
    "engine/crates/legion-contracts/src",
    "engine/crates/legion-rules/src",
    "src/registry/rules",
    "src/registry/controls",
]
IMPL_FILES = [
    "engine/Cargo.lock",
    "engine/Cargo.toml",
    "engine/crates/legion-audit/Cargo.toml",
    "engine/crates/legion-effects/Cargo.toml",
    "engine/crates/legion-provider-sdk/Cargo.toml",
    "engine/crates/legion-contracts/Cargo.toml",
    "engine/crates/legion-rules/Cargo.toml",
]
CASES = {
    "shellcheck-unquoted": (
        "#!/bin/sh\nname=$1\necho $name\n",
        ["SC2086|src/check.sh|3"],
        1,
    ),
    "shellcheck-quoted": ("#!/bin/sh\nname=$1\necho \"$name\"\n", [], 0),
}


def compact(value):
    # Rust serde_json preserve_order serializes insertion order, which Python
    # dicts also preserve after parsing the receipt/registry files.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def generated_session_provenance(relative):
    return re.fullmatch(
        r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json",
        relative,
    ) is not None


def bound_file(root, path):
    require(not path.is_symlink(), f"symlink in source binding: {path}")
    require(path.is_file(), f"missing bound file: {path}")
    return (path.relative_to(root).as_posix(), digest(path.read_bytes()))


def check_binding(root, binding):
    provider_rows = json.loads((root / "src/registry/providers.json").read_bytes())["providers"]
    rows = [row for row in provider_rows if row.get("id") == PROVIDER]
    require(len(rows) == 1, "ShellCheck provider must have exactly one registry specification")
    # serde_json's preserve_order Map::remove swaps the final key into the
    # removed slot. Match the actual harness bytes rather than dict.pop order.
    items = list(rows[0].items())
    for index, (key, _) in enumerate(items):
        if key == "benchmark":
            items[index] = items[-1]
            items.pop()
            break
    spec = dict(items)
    require(binding["providerSpecDigest"] == digest(compact(spec)), "provider spec binding is stale")
    harness = root / HARNESS
    require(binding["harnessPath"] == HARNESS, "unexpected harness path")
    require(binding["harnessDigest"] == digest(harness.read_bytes()), "harness binding is stale")

    files = []
    for tree in IMPL_TREES:
        base = root / tree
        require(base.is_dir(), f"missing implementation root: {tree}")
        for path in base.rglob("*"):
            require(not path.is_symlink(), f"symlink in implementation binding: {path}")
            if path.is_file():
                if generated_session_provenance(path.relative_to(root).as_posix()):
                    continue
                files.append(bound_file(root, path))
    for relative in IMPL_FILES:
        files.append(bound_file(root, root / relative))
    files.sort()
    implementation = binding["implementation"]
    require(implementation["roots"] == IMPL_TREES, "implementation roots differ")
    require(implementation["fileCount"] == len(files), "implementation file count differs")
    require(implementation["digest"] == digest(compact([list(row) for row in files])),
            "implementation binding is stale")


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def canonical_executable(value, label):
    path = Path(value)
    require(path.is_absolute() and path.exists() and path.is_file(), f"{label} executable missing")
    require(str(path.resolve()) == value, f"{label} path is not canonical")
    return path


def retained_executable(value, expected):
    """Validate archived macOS identity only; no claim about local binary bytes."""
    require(isinstance(value, str) and value.startswith("/") and not value.startswith("//"), "retained executable is not absolute")
    path = PurePosixPath(value)
    require(str(path) == value and ".." not in path.parts and is_digest(expected), "retained executable identity malformed")
    return path


def check_real_executables(cases, live=True):
    tool_paths, wrapper_paths = set(), set()
    for case in cases:
        policy = case["policy"]
        tool, wrapper = policy["tool"], policy["wrapper"]
        tool_path = retained_executable(tool["path"], tool["digest"])
        wrapper_path = retained_executable(wrapper["path"], wrapper["digest"])
        require(wrapper_path == PurePosixPath("/usr/bin/sandbox-exec"), "unexpected native sandbox wrapper")
        if live:
            tool_path = canonical_executable(tool["path"], "ShellCheck")
            wrapper_path = canonical_executable(wrapper["path"], "sandbox wrapper")
            require(os.access(tool_path, os.X_OK), "ShellCheck is not executable")
            tool_bytes = tool_path.read_bytes()
            require(not tool_bytes.startswith(b"#!"), "ShellCheck must be a host executable, not a script")
            require(tool["digest"] == digest(tool_bytes), "ShellCheck executable digest differs")
            require(wrapper["digest"] == digest(wrapper_path.read_bytes()), "sandbox wrapper digest differs")
        tool_paths.add(tool["path"])
        wrapper_paths.add(wrapper["path"])
    require(len(tool_paths) == len(wrapper_paths) == 1, "cases used different tool or wrapper identities")


def check_decisions(case, expected_root, run_root, tool_path):
    policy = case["policy"]
    require(policy["id"] == POLICY and policy["version"] == 1, "benchmark policy identity differs")
    require(policy["provider"] == PROVIDER, "policy provider differs")
    require(policy["root"] == expected_root and policy["runDirectory"] == run_root,
            "policy roots differ from recorded decisions")
    require(PurePosixPath(expected_root).is_absolute() and PurePosixPath(run_root).is_absolute(), "fixture roots must be absolute")
    require(PurePosixPath(expected_root).parent == PurePosixPath(run_root).parent, "fixture roots are not a paired source/run")
    require(PurePosixPath(expected_root).name == "source" and PurePosixPath(run_root).name == "run", "unexpected fixture layout")
    require(policy["scannerArgs"] == TOOL_ARGS and policy["versionArgs"] == ["--version"],
            "scanner or version arguments differ")
    require(policy["inventoryDigest"] == case["inventoryDigest"], "policy inventory digest differs")
    require(policy["sandbox"] == "native-macos-deny-network-deny-project-write", "sandbox policy differs")
    require(policy["timeoutMsMaximum"] == 30000 and policy["outputBytesMaximum"] == 1048576,
            "execution limits differ")
    decisions = case["policyDecisions"]
    require(len(decisions) == 2 and all(row.get("allowed") is True for row in decisions),
            "both version probe and scanner must be authorized")
    probe, scan = decisions
    require(probe["taskId"] == "shellcheck-version-probe", "version probe task missing")
    require(scan["taskId"] == "shellcheck", "scanner execution decision missing")
    require(probe["requestId"] != scan["requestId"] and all(
        row["providerId"] == PROVIDER and row["planId"] == case["inventoryDigest"] and
        row["cwd"] == expected_root and row["executable"] == "/usr/bin/sandbox-exec" and
        row["expectedDigest"] == case["policy"]["wrapper"]["digest"] and
        row["timeoutMs"] > 0 and row["timeoutMs"] <= 30000 and
        row["stdoutLimit"] > 0 and row["stdoutLimit"] <= 1048576 and
        row["stderrLimit"] > 0 and row["stderrLimit"] <= 1048576 and
        row["requiresNetworkSandbox"] is True for row in decisions), "decision scope differs")
    version_receipt = case["toolIdentity"]["version"]["receipt"]
    scanner_receipt_id = case["executionReceipt"]["receiptId"]
    require(probe["requestId"] == version_receipt["requestId"],
            "version decision request ID differs from native receipt")
    require(probe["requestId"].startswith("legion-audit/") and
            scan["requestId"].startswith("legion-audit/"), "request IDs were not artifact-scoped")
    require(scanner_receipt_id == "receipt:" + scan["requestId"],
            "scanner decision request ID differs from reduced receipt")
    probe_prefix = ["-f", probe["args"][1], "--", tool_path]
    scan_prefix = ["-f", scan["args"][1], "--", tool_path]
    require(probe["args"] == probe_prefix + ["--version"], "version probe argv differs")
    require(scan["args"] == scan_prefix + TOOL_ARGS, "scanner argv differs")
    require(probe["versionArgs"] == probe_prefix + ["--version"] and
            scan["versionArgs"] == scan_prefix + ["--version"],
            "qualified version arguments differ")
    for row in decisions:
        profile = PurePosixPath(row["args"][1])
        require(profile.is_absolute() and ".." not in profile.parts and profile.is_relative_to(PurePosixPath(run_root)),
                "sandbox profile escapes fixture run directory")
        escaped = expected_root.replace("\\", "\\\\").replace('"', '\\"')
        expected_profile = (f'(version 1)\n(allow default)\n(deny network*)\n'
                            f'(allow file-read* (subpath "{escaped}"))\n'
                            f'(deny file-write* (subpath "{escaped}"))\n').encode()
        profile_hash = hashlib.sha256(expected_profile).hexdigest()
        require(profile.name == f"audit-{profile_hash}.sb", "sandbox profile identity differs")
        require(PurePosixPath(row["args"][1]).parent.is_relative_to(PurePosixPath(run_root)),
                "sandbox profile directory escapes fixture")
    require(probe["acceptedExitCodes"] == [0] and scan["acceptedExitCodes"] == [0, 1],
            "accepted exit codes differ")


def check_version_probe(case):
    version = case["toolIdentity"]["version"]
    value = version["version"]
    raw = version["rawVersionOutput"]
    require(re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", value) is not None, "version is not numeric")
    require("ShellCheck" in raw, "version output does not identify ShellCheck")
    lines = [line.strip()[len("version:"):].strip() for line in raw.splitlines()
             if line.strip().startswith("version:")]
    require(lines == [value], "semantic version does not match full output")
    receipt = version["receipt"]
    require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["exitCode"] == 0,
            "native version probe did not complete")
    require(receipt["gaps"] == [] and receipt["processTree"] == {"started": True, "reaped": True},
            "version probe has execution gaps")
    require(receipt["policy"]["id"] == POLICY and receipt["policy"]["allowed"] is True and
            receipt["policy"]["version"] == 1 and is_digest(receipt["policy"]["digest"]),
            "version probe policy receipt missing")
    policy_bytes = compact(case["policy"])
    require(receipt["policy"]["digest"] == digest(policy_bytes), "version probe policy binding differs")
    require(receipt["executable"]["path"] == case["policy"]["wrapper"]["path"] and
            receipt["executable"]["digest"] == case["policy"]["wrapper"]["digest"],
            "version probe wrapper identity differs")
    identity = receipt["executable"]["version"]
    require(identity["qualified"] is True and identity["skippedByPolicy"] is False and identity["exitCode"] == 0,
            "version was not qualified by native probe")
    require(identity["args"] == case["policyDecisions"][0]["args"], "native version args differ")
    stdout = receipt["stdout"]
    require(stdout["immutable"] is True and stdout["bytes"] > 0 and is_digest(stdout["digest"]),
            "immutable version output artifact missing")
    require(receipt["parser"] == {"attempted": False, "succeeded": False, "error": None},
            "version receipt parser state differs from direct process execution")
    require(receipt["sandbox"]["required"] is True and receipt["sandbox"]["networkEnabled"] is True and
            receipt["sandbox"]["receiptId"] == "sandbox:macos:" +
            hashlib.sha256((f'(version 1)\n(allow default)\n(deny network*)\n'
                            f'(allow file-read* (subpath "{case["policy"]["root"]}"))\n'
                            f'(deny file-write* (subpath "{case["policy"]["root"]}"))\n').encode()).hexdigest(),
            "native sandbox receipt missing or inconsistent")


def check_case(case, case_id):
    source, expected, exit_code = CASES[case_id]
    require(case["caseId"] == case_id, "case ID differs")
    require(case["source"] == {"path": "src/check.sh", "bytes": source, "digest": digest(source.encode())},
            f"{case_id}: source fixture differs")
    require(case["expected"] == expected, f"{case_id}: expected labels differ")
    actual = case["actual"]
    require(isinstance(actual, list) and all(isinstance(label, str) for label in actual), "actual labels malformed")
    require(case["controlMatched"] is (actual == expected), f"{case_id}: control match bit is false")
    require(case["planDigest"] and case["inventoryDigest"], "frozen plan/inventory binding missing")
    require(case["coverage"] == {
        "denominator_digest": case["coverage"]["denominator_digest"],
        "expected": 1, "examined": 1, "gaps": []
    }, f"{case_id}: denominator is incomplete")
    require(is_digest(case["coverage"]["denominator_digest"]), "denominator digest malformed")
    result = case["actualProviderResult"]
    require(result["applicable"] is True and result["complete"] is True and result["findings"] == [] and
            result["coverage_gaps"] == [] and result["degradation"] == [], f"{case_id}: provider result incomplete")
    require(result["coverage"] == case["coverage"], f"{case_id}: provider result coverage differs")
    candidates = result["details"]["candidates"]
    candidate_labels = []
    for candidate in candidates:
        require(candidate["source"]["tool"] == "shellcheck" and candidate["adjudication"] == "required",
                f"{case_id}: candidate provenance differs")
        candidate_labels.append(f"{candidate['ruleId']}|{candidate['path']}|{candidate['line']}")
    require(actual == candidate_labels, f"{case_id}: reported labels differ from actual native candidates")

    policy = case["policy"]
    parent = PurePosixPath(policy["root"]).parent
    check_decisions(case, policy["root"], policy["runDirectory"], policy["tool"]["path"])
    require(not PurePosixPath(policy["tool"]["path"]).is_relative_to(parent), "tool executable lives inside disposable fixture")
    check_version_probe(case)

    receipt = case["executionReceipt"]
    require(result["details"]["executionReceipt"] == receipt, f"{case_id}: receipt differs from provider result")
    require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["offline"] is True,
            f"{case_id}: real scanner did not complete offline")
    require(receipt["tool"]["name"] == "shellcheck" and receipt["executableDigest"] == policy["tool"]["digest"],
            f"{case_id}: scanner tool identity differs")
    require(receipt["argv"] == ["shellcheck"] + TOOL_ARGS and receipt["exitCode"] == exit_code,
            f"{case_id}: scanner argv/exit code differs")
    require(receipt["policyId"] == POLICY and receipt["sandbox"]["required"] is True and
            receipt["sandbox"]["networkEnabled"] is True, f"{case_id}: reduced scanner receipt differs")
    require(receipt["sandbox"]["receiptId"] == case["toolIdentity"]["version"]["receipt"]["sandbox"]["receiptId"],
            "scanner sandbox receipt differs from the same-root version probe")
    require(is_digest(receipt["stdoutDigest"]) and receipt["stdoutBytes"] > 0, "scanner output artifact metadata missing")
    require(receipt["stdoutArtifact"] == {"digest": receipt["stdoutDigest"], "bytes": receipt["stdoutBytes"]},
            "scanner output artifact binding differs")


def validate(root, directory):
    require(directory.is_dir(), "receipt directory missing")
    entries = list(directory.iterdir())
    require(len(entries) == 1 and entries[0].name == "security_scanner-shellcheck.json" and
            entries[0].is_file() and not entries[0].is_symlink(), "expected exactly one ShellCheck receipt")
    record = json.loads(entries[0].read_bytes())
    return validate_record(root, record)


def validate_record(root, record, live=True):
    require(record["schema"] == "legion-external-provider-accuracy/1" and record["provider"] == PROVIDER,
            "unexpected external provider receipt")
    require(record["stage"] == "candidate" and record["executionPath"] ==
            "native-sdk-frozen-plan-real-external-scanner", "receipt is not from native frozen-plan execution")
    require(record["modelCalls"] == 0 and record["qualificationEligible"] is True and
            record["coverageState"] == "complete" and record["coverageGaps"] == [] and
            record["status"] == "pass", "receipt reports incomplete execution")
    require(record["scope"] == "Constructed planted & clean controls; not population accuracy or production admission",
            "scope statement differs")
    check_binding(root, record["binding"])
    cases = record["cases"]
    require([case["caseId"] for case in cases] == list(CASES), "missing, duplicate, or reordered control cases")
    check_real_executables(cases, live=live)
    for case, case_id in zip(cases, CASES):
        check_case(case, case_id)
    tp = fp = fn = positive = clean = 0
    for case in cases:
        wanted, actual = case["expected"], case["actual"]
        require(len(wanted) == len(set(wanted)), "duplicate expected output label")
        expected_set, actual_set = set(wanted), set(actual)
        tp += len(expected_set & actual_set)
        fp += len(actual_set - expected_set) + len(actual) - len(actual_set)
        fn += len(expected_set - actual_set)
        positive += bool(wanted)
        clean += not wanted
    require((positive, clean, fp, fn) == (1, 1, 0, 0), "positive/clean controls or exact outputs differ")
    metrics = {
        "truePositives": tp, "falsePositives": fp, "falseNegatives": fn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "positiveCases": positive, "cleanCases": clean,
    }
    require(record["metrics"] == metrics, "metrics do not match duplicate-preserving case output")
    body = dict(record)
    claimed = body.pop("qualificationDigest")
    require(claimed == digest(compact(body)), "qualification digest differs")
    return {"provider": PROVIDER, "qualificationEligible": True, "qualificationDigest": claimed,
            "metrics": metrics, "coverageState": "complete", "coverageGaps": []}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    result = validate(args.root.resolve(), args.receipts)
    print("EXTERNAL_PROVIDER_ACCURACY_SUMMARY " + json.dumps(result, sort_keys=True, separators=(",", ":")))
