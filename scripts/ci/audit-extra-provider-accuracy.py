#!/usr/bin/env python3
"""Validate source-bound Squawk & native legacy-linter controls."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy

common = runpy.run_path(str(Path(__file__).with_name("audit-real-provider-accuracy.py")))
compact, canonical, digest, require, is_digest, load, executable, artifact, native, sources = (
    common[name] for name in ("compact", "canonical", "digest", "require", "is_digest", "load", "executable", "artifact", "native", "sources"))
BASE = "engine/crates/legion-audit/tests/"
SQUAWK = "security.scanner-squawk"
ACTION, DOCKER, SWIFT = "legacy.security.github-actions-lint", "legacy.security.docker", "legacy.quality.swift-lint"
HARNESSES = {SQUAWK: BASE + "more_external_scanner_accuracy.rs",
             **{provider: BASE + "real_legacy_linter_accuracy.rs" for provider in (ACTION, DOCKER, SWIFT)}}
SCANNER_SCOPE = "Constructed planted & clean controls; not population accuracy or production admission"
RETENTION = "Scanner producer retains its actual reduced receipt, normalized raw findings & stdout digest; full scanner stdout/process-tree receipt is not retained. Separate real native version output & receipt are retained."
LINTERS = {
    ACTION: ("actionlint", "ci_lint", ".github/workflows/ci.yml", ["-format", "{{json .}}", "--", "./.github/workflows/ci.yml"],
             "name: CI\non: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n        uses: actions/checkout@v4\n",
             "name: CI\non: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"),
    DOCKER: ("hadolint", "docker", "Dockerfile", ["--format", "json", "Dockerfile"],
             'FROM ubuntu:latest\nCMD ["true"]\n', 'FROM ubuntu:24.04\nCMD ["true"]\n'),
    SWIFT: ("swiftlint", "swift_lint", "Example.swift", ["lint", "--quiet", "--reporter", "json"],
            "class example {}\n", "class Example {}\n"),
}


def same(actual, expected, message):
    require(canonical(actual) == canonical(expected), message)


def require_not_skipped_by_policy(version):
    # Native serde defaults an omitted skippedByPolicy bool to false.
    require(isinstance(version, dict) and {"args", "output", "exitCode", "qualified"} <= version.keys(),
            "version receipt fields missing")
    skipped = version.get("skippedByPolicy", False)
    require(type(skipped) is bool and skipped is False, "version probe skipped by policy")


def safe_absolute(value):
    path = PurePosixPath(value)
    require(path.is_absolute() and not value.startswith("//") and ".." not in path.parts and str(path) == value, "noncanonical retained path")
    return path


def request_id(value):
    require(isinstance(value, str) and re.fullmatch(r"legion-audit/[0-9a-f]{64}", value), "artifact request identity differs")


def profile_contract(root, writable=False):
    escaped = str(root).replace("\\", "\\\\").replace('"', '\\"')
    permissions = (f'(allow file-read* file-write* (subpath "{escaped}"))\n' if writable else
                   f'(allow file-read* (subpath "{escaped}"))\n(deny file-write* (subpath "{escaped}"))\n')
    text = "(version 1)\n(allow default)\n(deny network*)\n" + permissions
    hashed = digest(text.encode()).removeprefix("sha256:")
    return text, "audit-" + hashed + ".sb", "sandbox:macos:" + hashed


def scanner_args(tool, config="<owned-config-under-run>"):
    require(tool == "squawk", "unsupported scanner argv")
    return ["--reporter", "json", "-c", config, "--", "./migration.sql"]


def fixture(provider, positive):
    if provider in LINTERS:
        _, _, path, _, planted, clean = LINTERS[provider]
        return path, planted if positive else clean
    require(provider == SQUAWK, "unsupported fixture provider")
    return "migration.sql", ("SET lock_timeout = '1s';\nSET statement_timeout = '5s';\nALTER TABLE public.items DROP COLUMN IF EXISTS obsolete;\n" if positive else "SELECT 1;\n")


def bind(root, row, spec, files):
    provider, bound = row["provider"], row["binding"]
    items = list(spec.items())
    for index, (key, _) in enumerate(items):
        if key == "benchmark":
            items[index] = items[-1]
            items.pop()
            break
    spec, harness = dict(items), HARNESSES[provider]
    path = root / harness
    require(path.is_file() and not path.is_symlink(), "missing/symlink harness")
    encoding = canonical if provider in LINTERS else compact
    require(bound["providerSpecDigest"] == digest(encoding(spec)), "stale provider specification")
    if provider in LINTERS:
        expected = dict(files + [(harness, digest(path.read_bytes()))])
        same(bound["sources"], expected, "stale linter source inventory")
        require(bound["fixture"] == harness and bound["providerSpec"] == spec
                and bound["sourcesDigest"] == digest(canonical(expected)), "stale linter source/spec binding")
        fixture_sources = {fixture(provider, False)[0]: digest(fixture(provider, False)[1].encode())}
        same(bound["fixtureSources"], fixture_sources, "linter fixture binding differs")
        require(bound["fixtureSourcesDigest"] == digest(canonical(fixture_sources)), "linter fixture digest differs")
    else:
        require(bound["harnessPath"] == harness and bound["harnessDigest"] == digest(path.read_bytes()), "stale scanner harness")
        same(bound["implementation"], {"roots": common["shared"]["IMPL_TREES"], "fileCount": len(files),
                                      "digest": digest(compact([list(pair) for pair in files]))}, "stale scanner implementation")
        section = path.read_text().split("const EXPECTATION_SOURCES: &[&str] = &[", 1)[1].split("];", 1)[0]
        same(row["expectationSources"], re.findall(r'"(https://[^"\n]+)"', section), "expectation source inventory differs")


def scanner_case(case, provider, positive, live=True):
    tool = provider.removeprefix("security.scanner-")
    path, source = fixture(provider, positive)
    require(case["caseId"] == f"{tool}-{'planted' if positive else 'clean'}", "scanner case inventory differs")
    same(case["source"], {"path": path, "bytes": source, "digest": digest(source.encode())}, "scanner fixture differs")
    result, policy, receipt = case["actualProviderResult"], case["policy"], case["executionReceipt"]
    root, run = safe_absolute(policy["root"]), safe_absolute(policy["runDirectory"])
    require(root.name == "source" and run == root.parent / "run" and policy["provider"] == provider
            and policy["inventoryDigest"] == case["inventoryDigest"], "scanner fixture roots differ")
    policy_id = f"legion-{tool}-real-scanner-benchmark-v1"
    config = ""
    same(policy["ownedConfig"], {"bytes": config, "digest": digest(config.encode())}, "scanner config differs")
    require(policy["id"] == policy_id and policy["version"] == 1 and policy["scannerArgv"] == scanner_args(tool)
            and policy["versionArgv"] == ["--version"] and policy["timeoutMsMaximum"] == 30000
            and policy["outputBytesMaximum"] == 1048576 and policy["sandbox"] == "native-macos-deny-network-deny-project-write", "scanner policy differs")
    require(case["complete"] is True and case["coverageGaps"] == case["expectedCoverageGaps"] == []
            and case["controlMatched"] is True and case["coverageContractMatched"] is True
            and case["receiptRetentionLimit"] == RETENTION, "scanner evidence incomplete")
    require(result["provider"] == provider and result["applicable"] is True and result["complete"] is True
            and result["findings"] == result["coverage_gaps"] == result["degradation"] == [] and "availability" not in result["details"], "scanner result unavailable")
    coverage = case["coverage"]
    require(coverage == result["coverage"] and coverage["expected"] == coverage["examined"] == 1
            and coverage["gaps"] == [] and is_digest(coverage["denominator_digest"]), "scanner denominator differs")
    label = f"ban-drop-column|{path}|3"
    labels = []
    for candidate in result["details"]["candidates"]:
        origin, evidence = candidate["source"], candidate["evidence"][0]
        raw = origin["raw"]
        require(origin["tool"] == tool and candidate["adjudication"] == "required" and origin["rawFindingDigest"] == digest(compact(raw))
                and evidence["path"] == path and evidence["line"] == 3, "raw scanner candidate binding differs")
        require(raw["rule_name"] == "ban-drop-column" and raw["line"] == 2 and raw["file"].removeprefix("./") == path, "Squawk raw diagnostic differs")
        labels.append(f"{candidate['ruleId']}|{candidate['path']}|{candidate['line']}")
    same(case["expected"], [label] if positive else [], "scanner expected control differs")
    same(case["actual"], labels, "scanner actual projection differs")
    same(labels, case["expected"], "scanner native control differs")
    identity = case["toolIdentity"]
    same(policy["tool"], {"path": identity["path"], "digest": identity["executableDigest"]}, "scanner tool linkage differs")
    tool_path = executable(identity["path"], identity["executableDigest"], live=live)
    wrapper = executable(policy["wrapper"]["path"], policy["wrapper"]["digest"], live=live)
    require(wrapper == PurePosixPath("/usr/bin/sandbox-exec") and not tool_path.is_relative_to(root.parent), "scanner host tool differs")
    _, profile_name, sandbox_id = profile_contract(root)
    decisions = case["policyDecisions"]
    require(len(decisions) == 2, "scanner admission inventory differs")
    scan_profile = safe_absolute(decisions[1]["args"][1])
    require(scan_profile.is_relative_to(run) and scan_profile.parent.name == "sandbox" and scan_profile.name == profile_name, "scanner profile differs")
    args = scanner_args(tool, str(scan_profile.parent.parent / f"{tool}-owned-config"))
    for index, decision in enumerate(decisions):
        profile = run / "version-sandbox" / profile_name if index == 0 else scan_profile
        prefix = ["-f", str(profile), "--", str(tool_path)]
        request_id(decision["requestId"])
        require(decision["allowed"] is True and decision["providerId"] == provider and decision["planId"] == case["inventoryDigest"]
                and decision["taskId"] == (tool + "-version-probe" if index == 0 else tool) and decision["cwd"] == str(root)
                and decision["executable"] == str(wrapper) and decision["expectedDigest"] == policy["wrapper"]["digest"]
                and decision["args"] == prefix + (["--version"] if index == 0 else args) and decision["versionArgs"] == prefix + ["--version"]
                and decision["requiresNetworkSandbox"] is True and decision["acceptedExitCodes"] == ([0, 1] if index == 1 and provider == SQUAWK else [0])
                and 0 < decision["timeoutMs"] <= 30000 and all(0 < decision[key] <= 1048576 for key in ("stdoutLimit", "stderrLimit")), "scanner admission contract differs")
    version, probe = identity["version"], identity["version"]["receipt"]
    native(probe, policy_id, policy, compact)
    require(probe["schemaVersion"] == 1 and probe["requestId"] == decisions[0]["requestId"] and probe["receiptId"] == "receipt:" + probe["requestId"]
            and probe["providerId"] == provider and probe["planId"] == case["inventoryDigest"] and probe["taskId"] == tool + "-version-probe"
            and probe["cwd"] == str(root) and probe["exitCode"] == 0 and probe["signal"] is None
            and probe["executable"]["path"] == str(wrapper) and probe["executable"]["digest"] == policy["wrapper"]["digest"]
            and probe["executable"]["version"]["args"] == decisions[0]["args"], "scanner version receipt differs")
    require_not_skipped_by_policy(probe["executable"]["version"])
    for stream in ("stdout", "stderr"):
        artifact(probe[stream], probe[stream]["raw"])
    out, err = probe["stdout"]["raw"], probe["stderr"]["raw"]
    combined = out + ("\n" if out and err and not out.endswith("\n") else "") + err
    require(combined.strip() == version["rawVersionOutput"].strip() == probe["executable"]["version"]["output"].strip(), "scanner raw version differs")
    banner = next(line.strip() for line in combined.splitlines() if line.strip())
    require(receipt == result["details"]["executionReceipt"] and receipt["receiptId"] == "receipt:" + decisions[1]["requestId"]
            and receipt["state"] == "completed" and receipt["complete"] is True and receipt["offline"] is True and receipt["policyId"] == policy_id
            and receipt["tool"] == {"name": tool, "version": banner, "executableDigest": identity["executableDigest"]}
            and receipt["executableDigest"] == identity["executableDigest"] and receipt["argv"] == [tool] + args
            and receipt["exitCode"] == (1 if provider == SQUAWK and positive else 0), "scanner execution differs")
    same(receipt["sandbox"], {"required": True, "receiptId": sandbox_id, "networkEnabled": True}, "scanner sandbox differs")
    same(probe["sandbox"], receipt["sandbox"], "probe sandbox differs")
    require(is_digest(receipt["stdoutDigest"]) and type(receipt["stdoutBytes"]) is int and receipt["stdoutBytes"] > 0
            and receipt["stdoutArtifact"] == {"digest": receipt["stdoutDigest"], "bytes": receipt["stdoutBytes"]}, "reduced scanner output binding differs")


def linter_case(case, provider, positive, live=True):
    tool, task, path, args, _, _ = LINTERS[provider]
    _, source = fixture(provider, positive)
    require(case["caseId"] == provider.replace(".", "-") + ("-positive" if positive else "-absence")
            and case["control"] == ("positive" if positive else "absence") and case["matched"] is True, "linter case inventory differs")
    same(case["fixtureFiles"], {path: source}, "linter fixture bytes differ")
    same(case["fixtureSources"], {path: digest(source.encode())}, "linter fixture digest differs")
    policy, receipt, details = case["policyDefinition"], case["executionReceipt"], case["nativeDetails"]
    root = safe_absolute(policy["cwd"])
    run = root.parent / "run"
    require(root.name == "source" and root.parent.name == case["caseId"], "linter fixture root differs")
    wrapper = executable(policy["wrapper"]["path"], policy["wrapper"]["digest"], live=live)
    tool_path = executable(policy["tool"]["path"], policy["tool"]["digest"], live=live)
    require(wrapper == PurePosixPath("/usr/bin/sandbox-exec") and not tool_path.is_relative_to(root.parent.parent), "linter host tool differs")
    same(case["toolIdentity"], policy["tool"], "linter tool identity differs")
    text, profile_name, sandbox_id = profile_contract(root, writable=True)
    profile = run / "sandbox" / profile_name
    same(policy["profile"], {"path": str(profile), "text": text, "digest": digest(text.encode()), "receiptId": sandbox_id}, "native linter profile differs")
    prefix = ["-f", str(profile), "--", str(tool_path)]
    wrapped, version_args = prefix + args, prefix + ["--version"]
    require(policy["id"] == "legion-real-legacy-linter-qualification-v1" and policy["version"] == 1 and policy["provider"] == provider
            and policy["task"] == task and policy["plan"] == case["planDigest"] and policy["args"] == args
            and policy["wrappedArgs"] == wrapped and policy["versionArgs"] == version_args
            and policy["artifactRequestId"] == "legion-audit/<64 lowercase hex>; one admission only"
            and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 8388608
            and policy["sandbox"] == "native-macos-deny-network-production-linter-contract" and policy["acceptedExitCodes"] == [0, 1, 2], "linter policy contract differs")
    base = ["PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"]
    # Harness env_clear retains only PATH from its parent; HOME is fixture-local.
    # XDG_CONFIG_HOME/child TMPDIR are not inherited by expected_environment.
    retained_path = policy["environment"]["PATH"]
    require(isinstance(retained_path, str) and retained_path, "linter retained PATH missing")
    for part in retained_path.split(":"):
        safe_absolute(part)
    environment = {"PATH": os.environ["PATH"] if live else retained_path, "HOME": str(root.parent.parent / "home")}
    cache = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target",
             "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
    environment.update({name: str(run / relative) for name, relative in cache.items()})
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    same(policy["environment"], environment, "linter environment differs")
    same(policy["environmentAllowlist"], sorted(set(base + list(cache) + ["PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM"])), "linter environment allowlist differs")
    native(receipt, policy["id"], policy, canonical)
    decisions = case["policyDecisions"]
    require(len(decisions) == 1, "linter admission inventory differs")
    decision = decisions[0]
    request_id(receipt["requestId"])
    require(receipt["schemaVersion"] == 1 and decision["requestId"] == receipt["requestId"] and receipt["receiptId"] == "receipt:" + receipt["requestId"]
            and decision["allowed"] is True and receipt["providerId"] == decision["providerId"] == provider
            and receipt["planId"] == decision["planId"] == case["planDigest"] and receipt["taskId"] == decision["taskId"] == task
            and receipt["cwd"] == decision["cwd"] == str(root) and receipt["command"]["args"] == decision["args"] == wrapped
            and receipt["command"]["executable"] == receipt["executable"]["canonicalPath"] == decision["executable"] == str(wrapper)
            and receipt["executable"]["digest"] == decision["expectedDigest"] == policy["wrapper"]["digest"]
            and receipt["executable"]["version"]["args"] == decision["versionArgs"] == version_args
            and receipt["signal"] is None
            and receipt["exitCode"] == (0 if not positive else 2 if provider == SWIFT else 1), "linter native admission linkage differs")
    require_not_skipped_by_policy(receipt["executable"]["version"])
    require(decision["requiresNetworkSandbox"] is True and decision["acceptedExitCodes"] == [0, 1, 2]
            and decision["timeoutMs"] == 120000 and decision["stdoutLimit"] == decision["stderrLimit"] == 8388608
            and decision["environmentNames"] == sorted(environment) and decision["environmentDigest"] == digest(canonical(environment)), "linter native bounds/environment differ")
    same(decision["sandbox"], {"id": sandbox_id, "network": True, "filesystemScope": str(root)}, "linter admission sandbox differs")
    same(receipt["sandbox"], {"required": True, "receiptId": sandbox_id, "networkEnabled": True}, "linter executed sandbox differs")
    version = receipt["executable"]["version"]
    same(case["toolVersion"], {"output": version["output"], "exitCode": 0, "args": version_args, "qualified": True}, "linter retained version differs")
    stdout = case["actualStdout"]
    require(case["actualStderr"] == "", "linter stderr differs")
    artifact(receipt["stdout"], stdout)
    artifact(receipt["stderr"], "")
    report = json.loads(stdout)
    require(report is None or isinstance(report, list), "linter output is not JSON diagnostics")
    report = [] if report is None else report
    require(len(report) == int(positive) == case["expectedToolReportCount"] == case["actualToolReportCount"], "linter diagnostic count differs")
    if positive and provider == DOCKER:
        require(report[0]["code"] == "DL3007", "Hadolint diagnostic differs")
    if positive and provider == SWIFT:
        require(report[0]["rule_id"] == "type_name" and report[0]["severity"] == "Error"
                and report[0]["file"] == str(root / path) and report[0]["line"] == 1, "SwiftLint diagnostic differs")
    coverage = case["coverage"]
    require(coverage["expected"] == coverage["examined"] == 1 and coverage["gaps"] == []
            and is_digest(coverage["denominatorDigest"]), "linter denominator incomplete")
    rule, claim = f"legacy.{task}.{tool}", f"{task} reported 1 finding(s)"
    finding_id = digest(f"{rule}\0{path}\0{1}".encode())
    candidates = [{"id": finding_id, "ruleId": rule, "role": "candidate-generator", "path": path, "line": 1,
                   "claim": claim, "severityHint": "medium", "evidenceStrength": "candidate", "verdict": "UNADJUDICATED", "adjudicationRequired": True}] if positive and provider != SWIFT else []
    expected = {"findingsCount": int(positive), "candidates": candidates}
    actual_candidates = [{**{key: candidate[key] for key in ("id", "ruleId", "role", "claim", "severityHint", "evidenceStrength", "verdict", "adjudicationRequired")},
                          "path": candidate["evidence"][0]["file"], "line": candidate["evidence"][0]["line"]} for candidate in details["candidates"]]
    actual = {"findingsCount": details["findingsCount"], "candidates": actual_candidates}
    if provider == SWIFT:
        expected.update({"findings": [{"id": finding_id, "severity": "medium"}] if positive else [],
                         "findingEvidence": {finding_id: {"ruleId": rule, "path": path, "line": 1, "message": claim}} if positive else {},
                         "findingLocations": {finding_id: [path + ":1"]} if positive else {}})
        actual.update({"findings": case["nativeFindings"], "findingEvidence": details.get("findingEvidence", {}), "findingLocations": details.get("findingLocations", {})})
    else:
        require(case["nativeFindings"] == [], "candidate linter promoted findings")
    require(case["outputKind"] == ("findings" if provider == SWIFT else "candidates") and receipt == details["executionReceipt"], "linter output stage/receipt differs")
    same(case["expected"], expected, "linter independent expected output differs")
    same(case["actual"], actual, "linter native actual projection differs")
    same(actual, expected, "linter native control differs")
    bundle = case["nativeDiagnostic"]
    raw = bundle["rawBytes"]
    require(isinstance(raw, list) and all(type(value) is int and 0 <= value <= 255 for value in raw), "linter diagnostic bytes malformed")
    data = bytes(raw)
    diagnostic = json.loads(data)
    same(bundle["diagnostic"], diagnostic, "linter diagnostic projection differs")
    retained = bundle["retainedArtifact"]
    path = safe_absolute(retained["path"])
    require(path.parent.name == "native-diagnostics" and path.name == "native-diagnostic-" + digest(data).removeprefix("sha256:") + ".json"
            and retained["digest"] == digest(data) and retained["bytes"] == len(data) and retained["qualificationEligible"] is False, "linter retained diagnostic differs")
    if live:
        require(Path(path).is_file() and not Path(path).is_symlink() and Path(path).read_bytes() == data, "linter retained diagnostic bytes differ")
    require(diagnostic["schema"] == "legion-native-linter-diagnostic/1" and diagnostic["caseId"] == case["caseId"]
            and len(diagnostic["results"]) == 1 and len(diagnostic["execution"]["results"]) == 1, "linter diagnostic result inventory differs")
    same(diagnostic["policyDecisions"], case["policyDecisions"], "linter diagnostic admissions differ")
    result = diagnostic["results"][0]
    require(result["provider"] == provider, "linter diagnostic provider differs")
    same(result["actualProviderResult"]["details"], details, "linter diagnostic actual details differ")
    same(result["actualProviderResult"]["findings"], case["nativeFindings"], "linter diagnostic findings differ")
    for stream, text in (("stdout", case["actualStdout"]), ("stderr", case["actualStderr"])):
        item = result["streams"][stream]
        same(item["artifact"], receipt[stream], "linter diagnostic stream receipt differs")
        require(item["rawBytes"] == list(text.encode()) and item["raw"] == text and item["actualDigest"] == digest(text.encode()), "linter diagnostic raw stream differs")



def validate(root, directory, providers, registry, files):
    diagnostic_required = any(provider in LINTERS for provider in providers)
    expected_names = {provider.replace(".", "_") + ".json" for provider in providers}
    if diagnostic_required:
        expected_names.add("native-diagnostics")
    require(directory.is_dir() and not directory.is_symlink() and {path.name for path in directory.iterdir()} == expected_names, "receipt file inventory differs")
    records = []
    for provider in providers:
        path = directory / (provider.replace(".", "_") + ".json")
        require(path.is_file() and not path.is_symlink(), "receipt must be regular nonsymlink file")
        row = load(path)
        require(row["provider"] == provider, "receipt filename/provider differs")
        records.append(row)
    summary = validate_records(root, records, registry, files)
    if diagnostic_required:
        diagnostics = directory / "native-diagnostics"
        require(diagnostics.is_dir() and not diagnostics.is_symlink(), "diagnostic directory missing/symlink")
        expected = set()
        for row in records:
            for case in row["cases"]:
                for bundle in [case["nativeDiagnostic"]]:
                    path = Path(bundle["retainedArtifact"]["path"])
                    require(path.parent == diagnostics.resolve() and path.is_file() and not path.is_symlink(), "diagnostic escaped retained root")
                    expected.add(path.name)
        require({path.name for path in diagnostics.iterdir()} == expected and len(expected) == 2 * len(providers), "retained diagnostic inventory differs")
    return summary


def validate_records(root, records, registry, files, live=True):
    """Reuse native semantics offline without claiming installed tool/gem bytes."""
    require(len({row["provider"] for row in records}) == len(records), "duplicate provider record")
    summary = []
    for row in records:
        provider = row["provider"]
        require(provider in HARNESSES, "unsupported provider adapter")
        legacy = provider in LINTERS
        require(row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0
                and row["coverageState"] == "complete" and row["schema"] == ("legion-real-linter-provider-accuracy/1" if legacy else "legion-external-provider-accuracy/1")
                and row["executionPath"] == ("native-sdk-frozen-plan-real-linter" if legacy else "native-sdk-frozen-plan-real-external-scanner")
                and row["stage"] == ("finding" if provider == SWIFT else "candidate"), "provider identity/status/stage differs")
        bind(root, row, registry[provider], files)
        cases = row["cases"]
        require(len(cases) == 2 and all(is_digest(case["planDigest"]) and is_digest(case["inventoryDigest"]) for case in cases), "frozen control inventory differs")
        for case, positive in zip(cases, (True, False)):
            (linter_case if legacy else scanner_case)(case, provider, positive, live=live)
        keys = ("path", "digest") if legacy else ("path", "executableDigest")
        same({key: cases[0]["toolIdentity"][key] for key in keys}, {key: cases[1]["toolIdentity"][key] for key in keys}, "tool identity changed between controls")
        if legacy:
            require(row["providerVersion"] == registry[provider]["providerVersion"] and row["outputKind"] == ("findings" if provider == SWIFT else "candidates")
                    and row["scope"] == "one actual tool diagnostic and one clean input; " + ("deterministic summary finding only" if provider == SWIFT else "candidates remain unadjudicated")
                    and all(case["toolVersion"]["output"] == row["toolVersion"] for case in cases), "linter claim/version differs")
            metrics = {"cases": 2, "matched": 2, "mismatched": 0}
        else:
            require(row["qualificationEligible"] is True and row["coverageGaps"] == [] and row["scope"] == SCANNER_SCOPE, "scanner qualification scope differs")
            tp = fp = fn = 0
            for case in cases:
                expected, actual = Counter(case["expected"]), Counter(case["actual"])
                tp += sum((expected & actual).values())
                fp += sum((actual - expected).values())
                fn += sum((expected - actual).values())
            metrics = {"truePositives": tp, "falsePositives": fp, "falseNegatives": fn, "precision": tp / (tp + fp) if tp + fp else 0.0,
                       "recall": tp / (tp + fn) if tp + fn else 0.0, "positiveCases": 1, "cleanCases": 1}
        same(row["metrics"], metrics, "metrics differ from native control outputs")
        body = dict(row)
        claimed = body.pop("qualificationDigest")
        require(claimed == digest((canonical if legacy else compact)(body)), "qualification digest differs")
        summary.append({"provider": provider, "stage": row["stage"], "coverageState": "complete", "qualificationDigest": claimed, "metrics": metrics})
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "squawk-receipts", "linter-receipts"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    registry_path = root / "src/registry/providers.json"
    require(registry_path.is_file() and not registry_path.is_symlink(), "missing/symlink registry")
    rows = load(registry_path)["providers"]
    require(all(sum(row["id"] == provider for row in rows) == 1 for provider in HARNESSES), "provider specification inventory differs")
    registry, files = {row["id"]: row for row in rows}, sources(root)
    summary = []
    for directory, providers in ((args.squawk_receipts, [SQUAWK]), (args.linter_receipts, [ACTION, DOCKER, SWIFT])):
        summary += validate(root, directory, providers, registry, files)
    print("EXTRA_PROVIDER_ACCURACY_SUMMARY " + json.dumps({"records": summary, "modelCalls": 0}, sort_keys=True, separators=(",", ":")))
