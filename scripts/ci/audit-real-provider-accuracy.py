#!/usr/bin/env python3
"""Validate source-bound real Zizmor, kube-linter & Git control receipts only."""

import argparse
import json
import os
import re
from pathlib import Path, PurePosixPath
import runpy

shared = runpy.run_path(str(Path(__file__).with_name("audit-external-provider-accuracy.py")))
compact, digest, require, is_digest = (shared[name] for name in ("compact", "digest", "require", "is_digest"))
SCANNER = "engine/crates/legion-audit/tests/additional_external_scanner_accuracy.rs"
GIT = "engine/crates/legion-audit/tests/legacy_git_accuracy.rs"
REPO, DEBT = "legacy.core.repo", "legacy.quality.debt-markers"
SCANNERS = ["security.scanner-zizmor", "security.scanner-kube-linter"]
CLEAN = "export const answer = 42;\n"
MARKER = "// TODO: remove compatibility branch\n" + CLEAN
# Independent contracts from SCANNER's Scanner::argv/ScopedPolicy & native sandbox renderer.
KUBE_CONFIG = "checks:\n  doNotAutoAddDefaults: true\n  include:\n    - privileged-container\n    - privilege-escalation-container\n    - host-network\n    - host-pid\n    - host-ipc\n    - sensitive-host-mounts\n    - wildcard-in-rules\n    - cluster-admin-role-binding\n    - writable-host-mount\n    - unsafe-proc-mount\n    - run-as-non-root\n    - no-read-only-root-fs\n"


def scanner_argv(tool, config="<owned-config-under-run>"):
    return (["--offline", "--no-config", "--no-progress", "--no-exit-codes", "--color", "never", "--format", "json-v1", "--", "./.github/workflows/ci.yml"]
            if tool == "zizmor" else ["lint", "--config", config, "--format", "json", "--", "./pod.yaml"])


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def load(path):
    def pairs(items):
        require(len(items) == len(dict(items)), f"duplicate JSON key in {path}")
        return dict(items)
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, f"non-JSON number: {value}"))


def generated_session_provenance(relative):
    return re.fullmatch(
        r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json",
        relative,
    ) is not None


def sources(root):
    files = []
    for relative in shared["IMPL_TREES"] + shared["IMPL_FILES"]:
        base = root / relative
        require(not base.is_symlink() and base.exists(), f"missing/symlink binding: {relative}")
        for path in base.rglob("*") if base.is_dir() else [base]:
            require(not path.is_symlink(), f"symlink in binding: {path}")
            if path.is_file():
                if generated_session_provenance(path.relative_to(root).as_posix()):
                    continue
                files.append(shared["bound_file"](root, path))
    return sorted(files)


def binding(root, row, registry, files, git):
    bound, spec = row["binding"], dict(registry[row["provider"]])
    # serde_json preserve_order Map::remove swap-removes, unlike dict.pop.
    if "benchmark" in spec:
        items = list(spec.items())
        index = list(spec).index("benchmark")
        last = items.pop()
        if index < len(items):
            items[index] = last
        spec = dict(items)
    require(bound["providerSpecDigest"] == digest(canonical(spec) if git else compact(spec)), "stale provider spec")
    harness = GIT if git else SCANNER
    require(not (root / harness).is_symlink(), "symlink harness")
    if git:
        expected = dict(files + [shared["bound_file"](root, root / harness)])
        require(bound["fixture"] == harness and bound["providerSpec"] == spec, "Git specification/fixture differs")
        require(bound["sources"] == expected and bound["sourcesDigest"] == digest(canonical(expected)), "stale Git sources")
    else:
        require(bound["harnessPath"] == harness and bound["harnessDigest"] == digest((root / harness).read_bytes()), "stale scanner harness")
        require(bound["implementation"] == {"roots": shared["IMPL_TREES"], "fileCount": len(files),
                                            "digest": digest(compact([list(pair) for pair in files]))}, "stale scanner implementation")


def executable(path, expected, live=True):
    retained = shared["retained_executable"](path, expected)
    if not live:
        return retained
    real = shared["canonical_executable"](path, "recorded tool")
    data = real.read_bytes()
    require(os.access(real, os.X_OK) and not data.startswith(b"#!") and digest(data) == expected, "executable identity differs")
    return real


def artifact(item, raw):
    path = Path(item["path"])
    require(not path.is_absolute() and ".." not in path.parts and item["immutable"] is True, "unsafe/nonimmutable output artifact")
    require(item["digest"] == digest(raw.encode()) and type(item["bytes"]) is int and item["bytes"] == len(raw.encode()), "output artifact differs")


def native(receipt, policy, definition, encoding):
    require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["gaps"] == [], "native execution incomplete")
    require(all(receipt["processTree"][key] is True for key in ("started", "terminated", "reaped")), "native process evidence incomplete")
    require(receipt["policyId"] == policy and receipt["policy"]["allowed"] is True and receipt["policy"]["id"] == policy
            and receipt["policy"]["version"] == 1 and receipt["policy"]["digest"] == digest(encoding(definition)), "native policy binding differs")
    version = receipt["executable"]["version"]
    require(version["qualified"] is True and version["exitCode"] == 0 and isinstance(version["output"], str)
            and version["output"].strip(), "real version evidence missing")


def scanner_case(case, provider, positive, live=True):
    tool = provider.removeprefix("security.scanner-")
    require(case["caseId"] == f"{tool}-{'planted' if positive else 'clean'}", "scanner control inventory differs")
    if tool == "zizmor":
        ref = "main" if positive else "11bd71901bbe5b1630ceea73d27597364c9af683"
        source = f"name: CI\non: [push]\npermissions:\n  contents: read\njobs:\n  check:\n    name: Check\n    runs-on: ubuntu-latest\n    steps:\n      - name: Checkout\n        uses: actions/checkout@{ref}\n        with:\n          persist-credentials: false\n"
        path, labels, version_args = ".github/workflows/ci.yml", ["unpinned-uses|.github/workflows/ci.yml|11"], ["--version"]
    else:
        source = f"apiVersion: v1\nkind: Pod\nmetadata:\n  name: scanner-fixture\nspec:\n  hostNetwork: false\n  hostPID: false\n  hostIPC: false\n  securityContext:\n    runAsNonRoot: true\n  containers:\n    - name: app\n      image: example.invalid/app@sha256:{'a' * 64}\n      securityContext:\n        privileged: {str(positive).lower()}\n        allowPrivilegeEscalation: false\n        readOnlyRootFilesystem: true\n        runAsNonRoot: true\n"
        path, labels, version_args = "pod.yaml", ["privilege-escalation-container|pod.yaml|unresolved", "privileged-container|pod.yaml|unresolved"], ["version"]
    require(case["source"] == {"path": path, "bytes": source, "digest": digest(source.encode())}, "scanner fixture differs")
    result, policy, receipt = case["actualProviderResult"], case["policy"], case["executionReceipt"]
    source_root, run_root = PurePosixPath(policy["root"]), PurePosixPath(policy["runDirectory"])
    require(source_root.is_absolute() and run_root.is_absolute() and source_root.name == "source" and run_root.name == "run"
            and ".." not in source_root.parts + run_root.parts and source_root.parent == run_root.parent
            and policy["provider"] == provider and policy["inventoryDigest"] == case["inventoryDigest"], "scanner fixture roots/binding differ")
    require(policy["scannerArgv"] == scanner_argv(tool) and policy["ownedConfig"] == (
        {"bytes": KUBE_CONFIG, "digest": digest(KUBE_CONFIG.encode())} if tool == "kube-linter" else None)
        and policy["timeoutMsMaximum"] == 30000 and policy["outputBytesMaximum"] == 1048576
        and policy["sandbox"] == "native-macos-deny-network-deny-project-write", "scanner policy contract differs")
    require(case["complete"] is True and case["coverageGaps"] == case["expectedCoverageGaps"] == []
            and case["coverageContractMatched"] is True and case["controlMatched"] is True, "scanner coverage/control incomplete")
    require(result["provider"] == provider and result["applicable"] is True and result["complete"] is True
            and result["coverage_gaps"] == result["degradation"] == result["findings"] == [] and "availability" not in result["details"], "scanner result unavailable")
    coverage = case["coverage"]
    require(coverage == result["coverage"] and coverage["expected"] == coverage["examined"] == 1
            and coverage["gaps"] == [] and is_digest(coverage["denominator_digest"]), "scanner denominator differs")
    actual = []
    for candidate in result["details"]["candidates"]:
        origin = candidate["source"]
        require(origin["tool"] == tool and candidate["adjudication"] == "required"
                and origin["rawFindingDigest"] == digest(compact(origin["raw"])), "scanner raw candidate binding differs")
        if tool == "kube-linter":
            require(candidate["line"] is None and candidate["evidence"][0]["line"] is None and candidate["anchorKind"] == "file"
                    and candidate["anchorStatus"] == "scanner-reported" and origin["sourceDigest"] == origin["frozenSourceDigest"]
                    == candidate["evidence"][0]["sourceDigest"] == case["source"]["digest"], "kube file anchor differs")
        actual.append(f"{candidate['ruleId']}|{candidate['path']}|{candidate['line'] if candidate['line'] is not None else 'unresolved'}")
    require(case["expected"] == (labels if positive else []) and case["actual"] == actual == case["expected"], "scanner actual output differs")
    tool_path = executable(policy["tool"]["path"], policy["tool"]["digest"], live=live)
    wrapper = executable(policy["wrapper"]["path"], policy["wrapper"]["digest"], live=live)
    require(wrapper == PurePosixPath("/usr/bin/sandbox-exec") and not tool_path.is_relative_to(source_root.parent), "scanner host identity differs")
    identity, probe = case["toolIdentity"], case["toolIdentity"]["version"]["receipt"]
    require(identity["path"] == str(tool_path) and identity["executableDigest"] == policy["tool"]["digest"], "scanner tool identity mismatch")
    native(probe, "legion-additional-real-scanner-benchmark-v1", policy, compact)
    require(probe["providerId"] == provider and probe["planId"] == case["inventoryDigest"] and probe["exitCode"] == 0
            and probe["cwd"] == policy["root"] and probe["executable"]["path"] == str(wrapper)
            and probe["executable"]["digest"] == policy["wrapper"]["digest"] and probe["executable"]["version"]["skippedByPolicy"] is False, "probe identity differs")
    for stream in ("stdout", "stderr"):
        artifact(probe[stream], probe[stream]["raw"])
    out, err = probe["stdout"]["raw"], probe["stderr"]["raw"]
    combined = out + ("\n" if out and err and not out.endswith("\n") else "") + err
    require(combined.strip() == identity["version"]["rawVersionOutput"].strip() == probe["executable"]["version"]["output"].strip(), "probe version output differs")
    decisions = case["policyDecisions"]
    require(len(decisions) == 2 and all(d["allowed"] is True for d in decisions), "scanner admissions missing")
    require([d["taskId"] for d in decisions] == [tool + "-version-probe", tool] and policy["versionArgv"] == version_args, "scanner probe contract differs")
    escaped = str(source_root).replace("\\", "\\\\").replace('"', '\\"')
    profile = f'(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath "{escaped}"))\n(deny file-write* (subpath "{escaped}"))\n'
    profile_hash = digest(profile.encode()).removeprefix("sha256:")
    profile_name = f"audit-{profile_hash}.sb"
    scan_profile = PurePosixPath(decisions[1]["args"][1])
    require(scan_profile.is_absolute() and ".." not in scan_profile.parts and scan_profile.is_relative_to(run_root)
            and scan_profile.parent.name == "sandbox" and scan_profile.name == profile_name, "scanner profile path differs")
    scan_args = scanner_argv(tool, str(scan_profile.parent.parent / "kube-linter-owned-config.yaml"))
    for index, decision in enumerate(decisions):
        expected_profile = run_root / "version-sandbox" / profile_name if index == 0 else scan_profile
        prefix = ["-f", str(expected_profile), "--", str(tool_path)]
        require(decision["providerId"] == provider and decision["planId"] == case["inventoryDigest"] and decision["cwd"] == policy["root"]
                and decision["executable"] == str(wrapper) and decision["expectedDigest"] == policy["wrapper"]["digest"]
                and decision["args"] == prefix + (version_args if index == 0 else scan_args)
                and decision["versionArgs"] == prefix + version_args and decision["requiresNetworkSandbox"] is True
                and decision["acceptedExitCodes"] == ([0, 1] if index == 1 and tool == "kube-linter" else [0])
                and 0 < decision["timeoutMs"] <= 30000 and all(0 < decision[key] <= 1048576 for key in ("stdoutLimit", "stderrLimit")), "scanner decision contract differs")
    require(probe["taskId"] == tool + "-version-probe" and probe["requestId"] == decisions[0]["requestId"]
            and re.fullmatch(r"legion-audit/[0-9a-f]{64}", probe["requestId"]) is not None
            and probe["executable"]["version"]["args"] == decisions[0]["args"]
            and receipt["receiptId"] == "receipt:" + decisions[1]["requestId"] and receipt == result["details"]["executionReceipt"], "scanner receipt linkage differs")
    require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["offline"] is True and receipt["policyId"] == policy["id"]
            and receipt["tool"] == {"name": tool, "version": next(line.strip() for line in combined.splitlines() if line.strip()), "executableDigest": identity["executableDigest"]}
            and receipt["executableDigest"] == identity["executableDigest"] and receipt["argv"] == [tool] + scan_args
            and receipt["exitCode"] == (1 if tool == "kube-linter" and positive else 0), "scanner execution evidence differs")
    require(receipt["sandbox"] == probe["sandbox"] == {"required": True, "receiptId": "sandbox:macos:" + profile_hash, "networkEnabled": True}
            and is_digest(receipt["stdoutDigest"])
            and receipt["stdoutBytes"] > 0 and receipt["stdoutArtifact"] == {"digest": receipt["stdoutDigest"], "bytes": receipt["stdoutBytes"]}, "scanner sandbox/output evidence differs")


def git_case(case, provider, positive, live=True):
    require(case["caseId"] == provider.replace(".", "-") + ("-positive" if positive else "-absence")
            and case["control"] == ("positive" if positive else "absence"), "Git controls differ")
    source = MARKER if provider == DEBT and positive else ("export const answer = 43;\n" if provider == REPO and positive else CLEAN)
    require(case["fixtureSource"] == source and case["fixtureSourceDigest"] == digest(source.encode()), "Git fixture differs")
    stdout = " M src/example.js\n" if provider == REPO and positive else ("src/example.js:1:// TODO: remove compatibility branch\n" if positive else "")
    expected = ({"repositoryStatus": " M src/example.js"} if positive else {}) if provider == REPO else {
        "findingsCount": int(positive), "ponytail": 0, "ponytailNoTrigger": 0, "todoFixme": int(positive), "findings": [
            {"ruleId": "legacy.debt_markers.git-grep", "path": "src/example.js", "line": 1,
             "message": "debt_markers reported 1 finding(s)", "severity": "low"}] if positive else []}
    details, receipt, policy = case["nativeDetails"], case["executionReceipt"], case["policyDefinition"]
    actual = ({"repositoryStatus": details["repositoryStatus"]} if "repositoryStatus" in details else {}) if provider == REPO else {
        **{key: details[key] for key in ("findingsCount", "ponytail", "ponytailNoTrigger", "todoFixme")},
        "findings": [dict(details["findingEvidence"][finding["id"]], severity=finding["severity"]) for finding in case["nativeFindings"]]}
    require(case["expected"] == case["actual"] == actual == expected and case["matched"] is True, "Git native output differs")
    require(case["actualStdout"] == case["expectedStdout"] == stdout and case["actualStderr"] == case["expectedStderr"] == "", "Git raw streams differ")
    require(not details.get("candidates", []) and (provider != REPO or case["nativeFindings"] == []), "Git stage differs")
    coverage = case["coverage"]
    require(coverage["expected"] == coverage["examined"] == 1 and coverage["gaps"] == [] and is_digest(coverage["denominatorDigest"]), "Git denominator incomplete")
    native(receipt, "legion-real-git-qualification-v1", policy, canonical)
    task, args = ("repo", ["status", "--porcelain=v1"]) if provider == REPO else ("debt_markers", ["grep", "-nIE", "(ponytail:|TODO|FIXME|HACK|XXX)"])
    accepted = [0] if provider == REPO else [0, 1]
    require(policy["task"] == task and policy["args"] == args and policy["versionArgs"] == ["--version"]
            and policy["sandbox"] == "not-required-by-shipped-read-only-git-contract" and policy["acceptedExitCodes"] == accepted
            and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 8388608, "Git policy contract differs")
    tool = executable(policy["executable"], policy["executableDigest"], live=live)
    require(PurePosixPath(policy["cwd"]).is_absolute() and ".." not in PurePosixPath(policy["cwd"]).parts
            and PurePosixPath(policy["cwd"]).name == "source" and not tool.is_relative_to(PurePosixPath(policy["cwd"]).parent)
            and policy["provider"] == provider and policy["plan"] == case["planDigest"], "Git fixture identity differs")
    require(receipt == details["executionReceipt"] and receipt["providerId"] == provider and receipt["planId"] == case["planDigest"]
            and receipt["cwd"] == policy["cwd"] and receipt["executable"]["canonicalPath"] == policy["executable"]
            and receipt["executable"]["digest"] == policy["executableDigest"] and receipt["executable"]["version"]["args"] == ["--version"]
            and receipt["executable"]["version"]["output"].strip() == policy["expectedVersionOutput"].strip()
            and policy["expectedVersionOutput"].startswith("git version "), "Git executable/version binding differs")
    require(receipt["sandbox"]["required"] is False and receipt["sandbox"]["receiptId"] is None
            and receipt["exitCode"] == (1 if provider == DEBT and not positive else 0), "Git execution contract differs")
    decisions = case["policyDecisions"]
    require(len(decisions) == 1 and decisions[0]["allowed"] is True and receipt["requestId"] == decisions[0]["requestId"]
            and receipt["receiptId"] == "receipt:" + decisions[0]["requestId"] and receipt["command"]["args"] == decisions[0]["args"] == args
            and receipt["taskId"] == decisions[0]["taskId"] == task, "Git admission linkage differs")
    require(decisions[0]["providerId"] == provider and decisions[0]["planId"] == case["planDigest"] and decisions[0]["cwd"] == policy["cwd"]
            and decisions[0]["executable"] == str(tool) and decisions[0]["expectedDigest"] == policy["executableDigest"]
            and decisions[0]["versionArgs"] == ["--version"] and decisions[0]["requiresNetworkSandbox"] is False
            and decisions[0]["acceptedExitCodes"] == accepted and decisions[0]["timeoutMs"] == 120000
            and decisions[0]["stdoutLimit"] == decisions[0]["stderrLimit"] == 8388608, "Git decision identity differs")
    # Child env_clear supplies only retained PATH & fixture HOME; SDK policy
    # binds every fixed override to the actual admitted request.
    source_root = PurePosixPath(policy["cwd"])
    run = source_root.parent / "run"
    base = ["PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"]
    retained_path = policy["environment"]["PATH"]
    require(isinstance(retained_path, str) and retained_path, "Git retained PATH missing")
    for part in retained_path.split(":"):
        path = PurePosixPath(part)
        require(path.is_absolute() and ".." not in path.parts, "Git PATH component unsafe")
    environment = {"PATH": os.environ["PATH"] if live else retained_path,
                   "HOME": str(source_root.parent.parent / "home")}
    cache = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target",
             "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
    environment.update({name: str(run / relative) for name, relative in cache.items()})
    fixed = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1"}
    environment.update(fixed)
    require(policy["environment"] == environment
            and policy["environmentAllowlist"] == sorted(set(base + list(cache) + list(fixed))), "Git exact child environment differs")
    require(decisions[0]["environmentNames"] == receipt["environmentNames"] == receipt["command"]["environmentNames"] == sorted(environment)
            and decisions[0]["environmentDigest"] == digest(canonical(environment)), "Git admitted environment binding differs")
    artifact(receipt["stdout"], stdout)
    artifact(receipt["stderr"], "")



def validate_native_diagnostics(directory, records):
    """Private raw artifacts stay distinct from eligible qualification records."""
    expected = {case["executionReceipt"]["receiptId"]: case
                for row in records if row["provider"] == "security.scanner-kube-linter"
                for case in row["cases"]}
    require(len(expected) == 2, "Kube diagnostic control inventory differs")
    directory = directory / "native-diagnostics"
    require(directory.is_dir() and not directory.is_symlink(), "native diagnostic directory missing/linked")
    paths = list(directory.iterdir())
    require(len(paths) == len(expected), "native diagnostic artifact inventory differs")
    seen = set()
    for path in paths:
        require(path.is_file() and not path.is_symlink(), "native diagnostic must be regular")
        data = path.read_bytes()
        require(len(data) <= 32 * 1048576
                and path.name == "native-diagnostic-" + digest(data).removeprefix("sha256:") + ".json",
                "native diagnostic content identity differs")
        row = load(path)
        receipt = row["receipt"]
        identity = receipt["receiptId"]
        require(identity in expected and identity not in seen, "native diagnostic control missing/duplicated")
        seen.add(identity)
        case = expected[identity]
        require(row["schema"] == "legion-native-scanner-diagnostic/1"
                and row["provider"] == receipt["providerId"] == case["actualProviderResult"]["provider"]
                and row["inventoryDigest"] == receipt["planId"] == case["inventoryDigest"],
                "native diagnostic frozen identity differs")
        native(receipt, case["policy"]["id"], case["policy"], compact)
        decision = case["policyDecisions"][1]
        reduced = case["executionReceipt"]
        require(receipt["requestId"] == decision["requestId"]
                and receipt["command"]["args"] == decision["args"]
                and receipt["cwd"] == decision["cwd"]
                and receipt["exitCode"] == reduced["exitCode"]
                and receipt["stdout"]["digest"] == reduced["stdoutDigest"]
                and receipt["stdout"]["bytes"] == reduced["stdoutBytes"],
                "native diagnostic actual execution linkage differs")
        for stream in ("stdout", "stderr"):
            record, original = row[stream], receipt[stream]
            require(isinstance(record, dict) and isinstance(original, dict), "native diagnostic stream missing")
            values = record["rawBytes"]
            require(isinstance(values, list) and len(values) <= 1048576
                    and all(type(value) is int and 0 <= value <= 255 for value in values),
                    "native diagnostic raw byte bounds differ")
            raw = bytes(values)
            require(record["originalPath"] == original["path"]
                    and record["digest"] == original["digest"] == digest(raw)
                    and type(record["bytes"]) is int and record["bytes"] == original["bytes"] == len(raw)
                    and record["immutable"] is original["immutable"] is True,
                    "native diagnostic stream identity differs")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            require(record["raw"] == text, "native diagnostic text projection differs")
    require(seen == set(expected), "native diagnostic controls incomplete")


def validate(root, directory, providers, registry, files, git=False):
    expected_files = {provider.replace(".", "_") + ".json" for provider in providers}
    if not git:
        expected_files.add("native-diagnostics")
    require(directory.is_dir() and {path.name for path in directory.iterdir()} == expected_files, "receipt file inventory differs")
    records = []
    for provider in providers:
        path = directory / (provider.replace(".", "_") + ".json")
        require(path.is_file() and not path.is_symlink(), "receipt must be a regular file")
        row = load(path)
        require(row["provider"] == provider, "receipt filename/provider differs")
        records.append(row)
    summaries = validate_records(root, records, registry, files, git=git)
    if not git:
        validate_native_diagnostics(directory, records)
    return summaries


def validate_records(root, records, registry, files, git=False, live=True):
    """Shared semantic checks; live=False retains identities without reading host tools."""
    require(len({row["provider"] for row in records}) == len(records), "duplicate provider record")
    summaries = []
    for row in records:
        provider = row["provider"]
        require(provider in ([REPO, DEBT] if git else SCANNERS), "unsupported provider adapter")
        require(row["schema"] == ("legion-real-git-provider-accuracy/1" if git else "legion-external-provider-accuracy/1")
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0 and row["status"] == "pass" and row["coverageState"] == "complete", "receipt identity/status differs")
        require(row["executionPath"] == ("native-sdk-frozen-plan-real-git" if git else "native-sdk-frozen-plan-real-external-scanner"), "execution path differs")
        require(row["stage"] == ("fact-output" if provider == REPO else "finding" if git else "candidate"), "output stage differs")
        binding(root, row, registry, files, git)
        cases = row["cases"]
        require(len(cases) == 2 and all(is_digest(c["planDigest"]) and is_digest(c["inventoryDigest"]) for c in cases), "frozen control inventory differs")
        for case, positive in zip(cases, (True, False)):
            (git_case if git else scanner_case)(case, provider, positive, live=live)
        if git:
            require(row["providerVersion"] == registry[provider]["providerVersion"] and row["outputKind"] == ("fact" if provider == REPO else "findings"), "Git output kind differs")
            require(row["scope"] == ("one dirty-path repository status & clean absence" if provider == REPO else "one summary finding & exact marker counts/raw grep; no marker-location accuracy claim"), "Git claim scope differs")
            system = row["systemGitConfig"]
            require(system == {"state": "disabled-by-child-environment", "environmentName": "GIT_CONFIG_NOSYSTEM", "environmentValue": "1"},
                    "system Git configuration not disabled by exact child environment")
            metrics = {"cases": 2, "matched": sum(c["expected"] == c["actual"] for c in cases), "mismatched": sum(c["expected"] != c["actual"] for c in cases)}
        else:
            require(row["qualificationEligible"] is True and row["coverageGaps"] == [] and row["scope"] == "Constructed planted & clean controls; not population accuracy or production admission", "scanner qualification/scope differs")
            tp = sum(len(set(c["expected"]) & set(c["actual"])) for c in cases)
            fp = sum(len(set(c["actual"]) - set(c["expected"])) + len(c["actual"]) - len(set(c["actual"])) for c in cases)
            fn = sum(len(set(c["expected"]) - set(c["actual"])) for c in cases)
            metrics = {"truePositives": tp, "falsePositives": fp, "falseNegatives": fn, "precision": tp / (tp + fp) if tp + fp else 0.0,
                       "recall": tp / (tp + fn) if tp + fn else 0.0, "positiveCases": 1, "cleanCases": 1}
        require(canonical(row["metrics"]) == canonical(metrics), "metrics differ from duplicate-preserving actual output")
        body = dict(row)
        claimed = body.pop("qualificationDigest")
        require(claimed == digest(canonical(body) if git else compact(body)), "qualification digest differs")
        summaries.append({"provider": provider, "stage": row["stage"], "qualificationDigest": claimed, "metrics": metrics, "coverageState": "complete"})
    return summaries


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scanner-receipts", type=Path, required=True)
    parser.add_argument("--git-receipts", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    rows = load(root / "src/registry/providers.json")["providers"]
    require(all(sum(row["id"] == provider for row in rows) == 1 for provider in SCANNERS + [REPO, DEBT]), "provider registry inventory differs")
    registry, files = {row["id"]: row for row in rows}, sources(root)
    summary = validate(root, args.scanner_receipts, SCANNERS, registry, files) + validate(root, args.git_receipts, [REPO, DEBT], registry, files, git=True)
    print("REAL_PROVIDER_ACCURACY_SUMMARY " + json.dumps({"records": summary, "modelCalls": 0}, sort_keys=True, separators=(",", ":")))
