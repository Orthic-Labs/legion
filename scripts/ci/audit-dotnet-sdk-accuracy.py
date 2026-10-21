#!/usr/bin/env python3
"""Validate retained actual .NET SDK observations; CI attestation stays separate.

No process is launched here. SDK receipts, raw artifacts, standard test results,
frozen inputs, source closure & every original language/task are cross-checked.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import runpy
import xml.etree.ElementTree as ET

ID = "code.dotnet"
POLICY = "legion-dotnet-sdk-qualification-v1"
LANGUAGES = ("csharp", "fsharp", "visualBasic")
TASKS = ("restore", "build", "analyzer", "test")
CONTROLS = ("positive", "nonempty-clean", "test-failure", "malformed", "missing-tool", "rejected-admission", "unsupported-framework", "unsupported-import", "source-drift", "package-drift", "sdk-drift")
LOOPBACK_APPROVAL = ".NET: approved — qualification-only loopback TCP admission for the VSTest harness process tree, recorded verbatim in code.dotnet’s record; external/non-loopback/UDP stay denied. Include in this batch."


def sandbox_admission():
    return {"approval": LOOPBACK_APPROVAL, "scope": "qualification-only VSTest harness process tree", "provider": ID,
            "task": "test", "transport": "TCP", "addresses": ["127.0.0.1", "::1"], "ports": "dynamic",
            "operations": ["bind", "inbound", "outbound"], "externalNetwork": False, "nonLoopback": False,
            "udp": False, "productionAdmission": False, "inheritedDescriptorConfinementProven": False}


def qualification_profiles(stage):
    baseline = '(version 1)\n(allow default)\n(deny network*)\n'
    file_rule = '(allow file-read* file-write* (subpath "' + str(stage).replace('\\', '\\\\').replace('"', '\\"') + '"))\n'
    loopback = ('(allow network-bind (require-all (local ip "localhost:*") (socket-type SOCK_STREAM)))\n'
                '(allow network-inbound (require-all (local ip "localhost:*") (socket-type SOCK_STREAM)))\n'
                '(allow network-outbound (require-all (remote ip "localhost:*") (socket-type SOCK_STREAM)))\n')
    return {task: baseline + (loopback if task == "test" else "") + file_rule for task in TASKS}


def sandbox_policy(policy, stage):
    same(policy["profiles"], qualification_profiles(stage), "sandbox task profiles differ")
    require(policy["wrapper"] == "/usr/bin/sandbox-exec" and policy["productionAdmission"] is False,
            "sandbox/policy definition differs")
    same([request["taskId"] for request in policy["requests"]], list(TASKS), "sandbox task definition differs")
    for request in policy["requests"]:
        profile_hash = digest(qualification_profiles(stage)[request["taskId"]].encode()).removeprefix("sha256:")
        prefix = ["-f", str(absolute(policy["scratch"]) / "sandbox" / ("audit-" + profile_hash + ".sb")), "--"]
        same(request["args"][:3], prefix, "sandbox command profile hash differs")
        same(request["versionArgs"][:3], prefix, "sandbox version profile hash differs")
        if request["sandbox"] is not None:
            same(request["sandbox"], {"id": "sandbox:macos:" + profile_hash, "network": True,
                                       "filesystemScope": str(stage)}, "sandbox receipt profile hash differs")


CRATES = ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")
SOURCE_DIRS = ["engine/crates/" + name + "/src" for name in CRATES] + ["src/registry/rules", "src/registry/controls"]
SOURCE_FILES = ["engine/crates/" + name + "/Cargo.toml" for name in CRATES] + ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", "scripts/ci/provision-dotnet-qualification-tools.py", "scripts/ci/audit-dotnet-sdk-accuracy.py", "scripts/ci/run-dotnet-sdk-qualification-child.py"]
REQUEST_FIELDS = {"schemaVersion", "requestId", "providerId", "planId", "policyId", "taskId", "executable", "args", "cwd", "origin", "shell", "expectedDigest", "acceptedExitCodes", "versionArgs", "skipVersionProbe", "versionRequirement", "environment", "environmentAllowlist", "sensitiveArgumentIndexes", "sensitiveEnvironmentNames", "requiresNetworkSandbox", "sandbox", "timeoutMs", "stdoutLimit", "stderrLimit"}
RECEIPT_FIELDS = {"schemaVersion", "receiptId", "requestId", "providerId", "planId", "policyId", "policy", "taskId", "state", "complete", "executable", "command", "cwd", "environmentNames", "sandbox", "processTree", "timing", "exitCode", "signal", "stdout", "stderr", "parser", "gaps"}
# A receipt refused by the native owner-admission policy also carries the frozen policy it was refused under.
POLICY_RECEIPT_FIELDS = RECEIPT_FIELDS | {"executionPolicy", "executionPolicyIdentity"}
OWNER_ADMISSION_POLICY = {"externalProcesses": "owner-admission-required", "admissionStatus": "unavailable", "effectiveMode": "deny-external"}


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def same(left, right, message):
    require(encoded(left) == encoded(right), message)


def parsed(raw):
    def pairs(rows):
        require(len(rows) == len(dict(rows)), "duplicate JSON key")
        return dict(rows)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def resolve_shared(row):
    """Expand `$sharedRef` digests from the record's `sharedValues` table into full subtrees.

    The harness stores identical large subtrees once; each reference is bound by the digest
    of the canonical stored value, checked here before any case-level comparison sees it.
    A stored value may itself reference other stored values, so expansion is recursive."""
    shared = row.get("sharedValues") or {}
    require(isinstance(shared, dict) and all(digest(encoded(v)) == k for k, v in shared.items()), "shared value digest differs")

    def expand(value):
        if isinstance(value, dict):
            if set(value) == {"$sharedRef"}:
                require(value["$sharedRef"] in shared, "shared reference unresolved")
                return expand(shared[value["$sharedRef"]])
            return {k: expand(v) for k, v in value.items()}
        if isinstance(value, list):
            return [expand(v) for v in value]
        return value

    out = dict(row)
    out["cases"] = expand(row["cases"])
    return out


def absolute(value):
    require(isinstance(value, str) and not any(c in value for c in "\0\r\n\\"), "invalid absolute path")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts and not value.startswith("//"), "noncanonical absolute path")
    return path


def relative(value):
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and str(path) == value and all(p not in (".", "..") for p in path.parts) and "\\" not in value, "unsafe relative path")
    return path


def byte_array(value):
    require(isinstance(value, list) and all(type(v) is int and 0 <= v <= 255 for v in value), "retained byte array malformed")
    return bytes(value)


def live_tree(root):
    require(root.is_dir() and not root.is_symlink(), "closure root missing/unsafe")
    rows = {}
    for path in root.rglob("*"):
        require(not path.is_symlink(), "closure symlink")
        if path.is_file():
            rows[path.relative_to(root).as_posix()] = digest(path.read_bytes())
        else:
            require(path.is_dir(), "closure special file")
    return rows


def generated_session_provenance(relative):
    return re.fullmatch(
        r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json",
        relative,
    ) is not None


def source_tree(repo, directory):
    require(directory.is_dir() and not directory.is_symlink(), "source root missing/unsafe")
    rows = {}
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "source closure symlink")
        if path.is_file():
            relative = path.relative_to(repo).as_posix()
            if generated_session_provenance(relative):
                continue
            rows[relative] = digest(path.read_bytes())
        else:
            require(path.is_dir(), "source closure special file")
    return rows


def source_binding(repo):
    rows = {}
    for directory in SOURCE_DIRS:
        rows.update(source_tree(repo, repo / directory))
    for name in SOURCE_FILES:
        path = repo / name
        require(path.is_file() and not path.is_symlink(), "source missing: " + name)
        rows[name] = digest(path.read_bytes())
    return rows


def source_files(root):
    return sorted(source_binding(Path(root)))


def artifact(item, receipt, scratch, live):
    if item is None:
        require(receipt is None, "receipt artifact has no retained bytes")
        return b""
    require(set(item) == {"path", "absolutePath", "digest", "bytes", "immutable", "rawBytes"}, "artifact fields differ")
    raw = byte_array(item["rawBytes"])
    path = relative(item["path"])
    require(item["immutable"] is True and item["bytes"] == len(raw) and item["digest"] == digest(raw), "artifact content differs")
    same(receipt, {key: item[key] for key in ("path", "digest", "bytes", "immutable")}, "artifact receipt linkage differs")
    full = absolute(item["absolutePath"])
    require(full == scratch / "artifacts" / path, "artifact escaped retained scratch")
    if live:
        require(Path(full).is_file() and not Path(full).is_symlink() and Path(full).read_bytes() == raw, "live artifact changed")
    return raw


def commands(language, task, scratch, enrollment):
    stage, control = scratch / "cache/dotnet-source", scratch / "cache/dotnet-control"
    ext = {"csharp": "csproj", "fsharp": "fsproj", "visualBasic": "vbproj"}[language]
    if task == "analyzer" and language == "fsharp":
        return [enrollment["fsharpAnalyzer"]["root"] + "/tools/net8.0/any/dotnet-fsharplint.dll", "--format", "MSBuild", "lint", str(stage / language / "**/*.fs"), "--lint-config", str(stage / "fsharplint.json")]
    args = ["build" if task == "analyzer" else task, str(stage / language / ("Fixture." + ext)), "--nologo", "--verbosity", "normal", "--artifacts-path", str(control / "artifacts-0"), "-p:NuGetAudit=false", "-p:RestoreIgnoreFailedSources=false", "-p:UseSharedCompilation=false", "-p:BuildInParallel=false", "-nodeReuse:false", "-p:ImportDirectoryBuildProps=false", "-p:ImportDirectoryBuildTargets=false", "-p:ImportDirectoryPackagesProps=false"]
    args += {"restore": ["--locked-mode", "--no-cache", "--disable-parallel", "--configfile", str(control / "NuGet.Config"), "--packages", enrollment["packagesRoot"]], "build": ["--no-restore", "-p:RunAnalyzers=false"], "analyzer": ["--no-restore", "-t:Rebuild", "-p:RunAnalyzers=true", "-p:RunAnalyzersDuringBuild=true", "-p:EnableNETAnalyzers=true", "-p:ReportAnalyzer=true"], "test": ["--no-restore", "--no-build", "--logger", "trx;LogFilePrefix=dotnet-sdk", "--results-directory", str(control / "test-results-0")]}[task]
    if task == "test":
        args += ["--diag", str(control / "vstest.log")]
    return args


def environment(req, scratch, enrollment, language, task):
    actual = req["environment"]
    control = scratch / "cache/dotnet-control"
    expected = {"PATH": enrollment["sdkRoot"], "NO_COLOR": "1", "CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never", "DOTNET_ROOT": enrollment["sdkRoot"], "DOTNET_MULTILEVEL_LOOKUP": "0", "DOTNET_ROLL_FORWARD": "LatestPatch", "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true", "DOTNET_NOLOGO": "1", "MSBUILDDISABLENODEREUSE": "1", "MSBuildEnableWorkloadResolver": "false", "NUGET_PACKAGES": enrollment["packagesRoot"], "NUGET_HTTP_CACHE_PATH": str(control / "http-cache"), "DOTNET_CLI_HOME": str(control / "home"), "LEGION_DOTNET_INPUT_MANIFEST": str(control / "inputs.json"), "LEGION_DOTNET_FRAMEWORKS": "net8.0", "LEGION_DOTNET_TEST_RESULTS": str(control / "test-results-0"), "HOME": str(control / "home"), "USERPROFILE": str(control / "home"), "XDG_CONFIG_HOME": str(control / "home/.config"), "MSBuildUserExtensionsPath": str(control / "home/msbuild"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1"}
    for name, path in (("TMPDIR", "tmp"), ("TEMP", "tmp"), ("TMP", "tmp"), ("XDG_CACHE_HOME", "cache/xdg"), ("CARGO_TARGET_DIR", "cache/cargo-target"), ("npm_config_cache", "cache/npm"), ("RUFF_CACHE_DIR", "cache/ruff"), ("MYPY_CACHE_DIR", "cache/mypy"), ("PYTHONPYCACHEPREFIX", "cache/pycache"), ("GOCACHE", "cache/go-build")):
        expected[name] = str(scratch / path)
    optional = {"PATHEXT", "SystemRoot", "COMSPEC", "CARGO_HOME", "RUSTUP_HOME", "GOPATH", "GOROOT", "GOMODCACHE"}
    if task == "test":
        expected["DOTNET_SYSTEM_NET_DISABLEIPV6"] = "1"
    if language == "fsharp" and task == "analyzer":
        expected["LEGION_DOTNET_FSHARP_FILES"] = json.dumps(["fsharp/Answer.fs", "fsharp/Tests.fs"], separators=(",", ":"))
    require(set(actual) - set(expected) <= optional, "unbound environment name")
    for name in optional & set(actual):
        expected[name] = actual[name]
    same(actual, expected, "SDK environment differs")
    allowed = set(expected) | {"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"}
    same(req["environmentAllowlist"], sorted(allowed), "SDK environment allowlist differs")


def execution(row, case, enrollment, live):
    require(set(row) == {"request", "executionReceipt", "stdout", "stderr"}, "SDK execution row fields differ")
    req, receipt = row["request"], row["executionReceipt"]
    require(set(req) == REQUEST_FIELDS and set(receipt) == (POLICY_RECEIPT_FIELDS if receipt.get("state") == "unauthorized_effect" else RECEIPT_FIELDS), "actual SDK request/receipt fields differ")
    policy = case["policyDefinition"]
    scratch = absolute(policy["scratch"])
    stage = scratch / "cache/dotnet-source"
    task, language = req["taskId"], case["language"]
    require(task in TASKS and re.fullmatch(r"legion-audit/[0-9a-f]{64}", req["requestId"]), "SDK request identity malformed")
    sandbox_policy(policy, stage)
    profile_text = qualification_profiles(stage)[task]
    profile_hash = digest(profile_text.encode()).removeprefix("sha256:")
    prefix = ["-f", str(scratch / "sandbox" / ("audit-" + profile_hash + ".sb")), "--", enrollment["sdkRoot"] + "/dotnet"]
    args = commands(language, task, scratch, enrollment)
    is_fsharp = language == "fsharp" and task == "analyzer"
    version_args = prefix + ([args[0], "--version"] if is_fsharp else ["--version"])
    environment(req, scratch, enrollment, language, task)
    expected = dict(req, schemaVersion=1, providerId=ID, planId=case["planDigest"], policyId="audit", executable="/usr/bin/sandbox-exec", args=prefix + args, cwd=str(stage), origin="TargetProject", shell=False, expectedDigest=policy["wrapperDigest"], acceptedExitCodes=[-1, 0, 255] if is_fsharp else [0] if task in ("restore", "test") else [0, 1], versionArgs=version_args, skipVersionProbe=False, versionRequirement=None, sensitiveArgumentIndexes=[], sensitiveEnvironmentNames=[], requiresNetworkSandbox=True, sandbox={"id": "sandbox:macos:" + profile_hash, "network": True, "filesystemScope": str(stage)}, timeoutMs=120000, stdoutLimit=33554432, stderrLimit=33554432)
    same(req, expected, "actual SDK request differs from independently reconstructed command")
    definition = next(r for r in policy["requests"] if r["taskId"] == task)
    same(dict(req, requestId="legion-audit/<content-digest>"), definition, "policy request definition differs")
    require(receipt["schemaVersion"] == 1 and receipt["receiptId"] == "receipt:" + req["requestId"] and receipt["requestId"] == req["requestId"] and receipt["providerId"] == ID and receipt["planId"] == case["planDigest"] and receipt["taskId"] == task and receipt["cwd"] == str(stage), "SDK receipt identity differs")
    same(receipt["command"], {"executable": req["executable"], "args": req["args"], "environmentNames": sorted(req["environment"]), "redactedArgumentIndexes": [], "redactedEnvironmentNames": []}, "SDK receipt command differs")
    same(receipt["environmentNames"], sorted(req["environment"]), "receipt environment differs")
    p = receipt["policy"]
    require(p and receipt["policyId"] == p["id"] and p["version"] == 1, "policy decision missing")
    if case["control"] == "rejected-admission":
        require(p["allowed"] is False and p["id"] == "audit-native-owner-admission-v1" and p["reason"] == "native-owner-admission-unavailable" and receipt["state"] == "unauthorized_effect" and receipt["complete"] is False and receipt["processTree"]["started"] is False and receipt["exitCode"] is None, "owner admission refusal differs")
        same(receipt["executionPolicy"], OWNER_ADMISSION_POLICY, "owner admission execution policy differs")
        same(receipt["executionPolicyIdentity"], {key: p[key] for key in ("id", "version", "digest")}, "owner admission policy identity differs")
        require(p["digest"] == digest(encoded(receipt["executionPolicy"])), "owner admission policy digest differs")
    else:
        require(p["id"] == POLICY and p["allowed"] is True and p["digest"] == digest(encoded(policy)), "exact fixture admission digest differs")
        tree = receipt["processTree"]
        require(tree["started"] is tree["terminated"] is tree["reaped"] is True and tree["hardKilled"] is False and receipt["signal"] is None, "actual SDK process lifecycle incomplete")
        identity = receipt["executable"]
        require(identity["requestedPath"] == identity["canonicalPath"] == "/usr/bin/sandbox-exec" and identity["digest"] == policy["wrapperDigest"] and identity["digestState"] == "sealed", "SDK executable identity differs")
        version = identity["version"]
        require(version["args"] == version_args and version["qualified"] is True and version["exitCode"] == 0 and version["skippedByPolicy"] is False and ("0.27.0" if is_fsharp else "8.0.426") in version["output"], "actual SDK/tool version probe differs")
        good = receipt["exitCode"] in req["acceptedExitCodes"]
        require(receipt["complete"] is good and receipt["state"] == ("completed" if good else "failed"), "SDK process outcome differs")
    same(receipt["sandbox"], {"required": True, "receiptId": "sandbox:macos:" + profile_hash, "networkEnabled": True}, "SDK authenticated sandbox differs")
    require(receipt["parser"] == {"attempted": False, "succeeded": False, "error": None}, "raw SDK receipt was replaced by parser result")
    out = artifact(row["stdout"], receipt["stdout"], scratch, live)
    err = artifact(row["stderr"], receipt["stderr"], scratch, live)
    if live:
        require(Path(prefix[1]).read_text() == profile_text and digest(Path("/usr/bin/sandbox-exec").read_bytes()) == policy["wrapperDigest"], "live wrapper/profile changed")
    return task, out.decode("utf-8"), err.decode("utf-8")


def standard_results(native, successful):
    retained = next(r for r in native if r["tool"] == "test")["dotnetStandardResults"]
    require(retained["error"] is None and isinstance(retained["retained"], list) and len(retained["retained"]) == 1, "actual framework TRX missing")
    row = retained["retained"][0]
    require(str(relative(row["path"])).endswith(".trx") and row["digest"] == digest(row["content"].encode()), "TRX retained bytes differ")
    xml = ET.fromstring(row["content"])
    counters = [e for e in xml.iter() if e.tag.split("}")[-1] == "Counters"]
    tests = [e for e in xml.iter() if e.tag.split("}")[-1] == "UnitTestResult"]
    require(len(counters) == 1, "TRX counter shape differs")
    counts = {k: int(v) for k, v in counters[0].attrib.items()}
    require(counts["total"] == counts["executed"] == len(tests) and len(tests) > 0, "TRX did not execute nonzero tests")
    if successful:
        require(counts["passed"] == len(tests) and all(t.attrib["outcome"] == "Passed" for t in tests) and all(counts.get(k, 0) == 0 for k in ("failed", "error", "timeout", "aborted", "notExecuted")), "TRX is not actual nonempty success")
    else:
        require(counts["failed"] > 0 and any(t.attrib["outcome"] == "Failed" for t in tests), "deliberate test failure missing from TRX")


def accounting(case, sources, language, project_extension, source_extension):
    inventory = case["inventory"]
    entries = [{"path": p, "symbols": [], "dependencies": [], "packageScripts": [],
                "sourceFile": p.endswith("." + source_extension), "digest": digest(raw)} for p, raw in sorted(sources.items())]
    generation = "filesystem:" + digest(encoded(entries))
    expected_inventory = {"schemaVersion": 1, "repositoryId": case["caseId"], "generation": generation,
                          "entries": entries, "digest": digest(encoded([1, case["caseId"], generation, entries]))}
    same(inventory, expected_inventory, "original frozen inventory differs from exact fixture")
    result = case["nativeResult"]
    require(result["provider"] == ID and result["schema_version"] == 1 and result["applicable"] is True and result["required"] is True, "native result provider identity differs")
    source_paths = sorted(p for p in sources if p.endswith("." + source_extension))
    context_paths = sorted(set(sources) - set(source_paths))
    source_rows, examined_sources = [], []
    for path in source_paths:
        if case["control"] == "source-drift" and "/Answer." in path:
            source_rows.append({"path": path, "extension": source_extension, "status": "skipped", "reason": "changed-since-inventory"})
        else:
            source_rows.append({"path": path, "extension": source_extension, "status": "examined", "bytes": len(sources[path]), "digest": digest(sources[path]), "analysis": "language-source"})
            examined_sources.append(path)
    context_rows = [{"path": p, "status": "examined", "analysis": "dotnet-sdk-frozen-context", "bytes": len(sources[p]), "digest": digest(sources[p])} for p in context_paths]
    producer = result["details"]["nativeProducer"]
    same(producer["sourceAccounting"], source_rows, "source accounting omitted/changed fixture bytes")
    same(producer["contextAccounting"], context_rows, "required context accounting omitted/changed frozen bytes")
    same(producer["context"], {"targetFrameworks": [language + "/Fixture." + project_extension]}, "actual required framework context changed")
    for key, expected in {"filesExpected": len(sources), "filesRead": len(examined_sources) + len(context_paths),
                          "sourceFilesExpected": len(source_paths), "sourceFilesRead": len(examined_sources),
                          "contextFilesExpected": len(context_paths), "contextFilesRead": len(context_paths),
                          "contextBytesRead": sum(len(sources[p]) for p in context_paths),
                          "bytesRead": sum(len(sources[p]) for p in examined_sources + context_paths)}.items():
        require(type(producer[key]) is int and producer[key] == expected, "native source/context count differs: " + key)
    require(producer["mode"] == "self-sourced", "native source mode differs")
    coverage = result["coverage"]
    require(set(coverage) == {"denominator_digest", "expected", "examined", "gaps"}
            and coverage["denominator_digest"] == inventory["digest"] and coverage["expected"] == len(sources)
            and coverage["examined"] == len(examined_sources) + len(context_paths), "native frozen coverage denominator differs")
    same(coverage["gaps"], result["coverage_gaps"], "native coverage gaps detached")
    analysis = result["details"]["nativeAnalysis"]
    same(analysis["denominator"], {"kind": "dotnet-files", "expected": 2, "examined": len(examined_sources), "variants": {l: 2 if l == language else 0 for l in LANGUAGES}}, "original language denominator changed")
    tools = analysis["toolEvidence"]
    same([t["id"] for t in tools], list(TASKS), "native tool accounting omitted original task")
    same(analysis["facts"], [{"kind": "native-metrics", "filesRead": len(examined_sources),
                             "linesRead": sum(len(sources[p].splitlines()) for p in examined_sources),
                             "bytesRead": sum(len(sources[p]) for p in examined_sources), "rules": producer["rules"]}], "native source metrics differ from frozen bytes")
    require(not any(g.get("context") == "targetFrameworks" for g in analysis["coverageGaps"]), "required context remains unavailable")
    if case["control"] in ("positive", "nonempty-clean"):
        require(result["status"] == "complete" and analysis["complete"] is True and not coverage["gaps"] and not analysis["coverageGaps"], "baseline coverage falsely clean/incomplete")
    else:
        require(result["complete"] is False and result["status"] == "partial" and coverage["gaps"], "negative control became complete coverage")


def positive_finding(case, sources, raw):
    language = case["language"]
    rule = "fsharplint:FL0014" if language == "fsharp" else "dotnet:CA1822"
    stage = absolute(case["policyDefinition"]["scratch"]) / "cache/dotnet-source"
    pattern = r"(?m)^(?:\d+>)?(.+?)\((\d+),\d+,\d+,\d+\):FSharpLint warning FL0014: (.+)$" if language == "fsharp" else r"(?m)^\s*(?:\d+>)?(.+?)\((\d+)(?:,\d+)?\): warning CA1822: (.+)$"  # MSBuild node prefix
    observed = []
    details = case["nativeResult"]["details"]
    refs = case["nativeResult"]["findings"]
    for path, line, message in re.findall(pattern, raw):
        path = PurePosixPath(path)
        relative_path = str(path.relative_to(stage)) if path.is_absolute() else str(path)
        require(relative_path in sources and 0 < int(line) <= len(sources[relative_path].splitlines()), "actual analyzer diagnostic escaped frozen source")
        finding_id = digest((ID + "\0" + rule + "\0" + relative_path + "\0" + line).encode())
        evidence = {"provider": ID, "ruleId": rule, "path": relative_path, "line": int(line), "message": message[:300]}
        same(details["findingEvidence"][finding_id], evidence, "actual diagnostic lost rule/location/evidence linkage")
        same(details["findingLocations"][finding_id], [relative_path + ":" + line], "actual finding location changed")
        require({"id": finding_id, "severity": "warning"} in refs, "real analyzer diagnostic has no hashed native finding reference")
        observed.append(finding_id)
    require(observed, "planted language-applicable analyzer rule missing")


def validate(repo, record, live=False):
    same(record["sandboxAdmission"], sandbox_admission(), "qualification loopback approval/scope differs")
    require(record["schema"] == "legion-dotnet-sdk-accuracy/1" and record["provider"] == ID and record["qualificationEligible"] is True and record["productionQualification"] is False and record["modelCalls"] == 0, "qualification envelope differs")
    require(record["kind"] == "dotnet-code-command-sdk-constructed" and record["claimScope"] == "known-answer-fixture-cases" and record["executionPath"] == "native-sdk-frozen-plan-self-sourced-code" and record["status"] == "observed-known-answer-controls" and record["missingControls"] == [] and record["executedScope"] == list(TASKS), "constructed execution scope differs")
    same(record["qualificationDigest"], digest(encoded({k: v for k, v in record.items() if k != "qualificationDigest"})), "qualification bytes changed")
    record = resolve_shared(record)
    same(record["sourceBinding"], source_binding(repo), "production/harness/source closure changed")
    spec = {k: v for k, v in next(p for p in parsed((repo / "src/registry/providers.json").read_bytes())["providers"] if p["id"] == ID).items() if k != "benchmark"}
    same(record["providerSpec"], spec, "original provider spec changed")
    required = next(p for p in parsed((repo / "src/registry/providers.json").read_bytes())["providers"] if p["id"] == ID)["benchmark"]["requiredForCleanClaim"]
    require(type(required) is bool and record["requiredForCleanClaim"] is required, "stable clean-claim policy changed")
    source_contract = (repo / "engine/crates/legion-audit/src/native_providers/code/dotnet.rs").read_text()
    for term in (*TASKS, "cs", "fs", "vb", *LANGUAGES, "targetFrameworks"):
        require('"' + term + '"' in source_contract, "original language contract changed")
    same(record["originalContract"], {"variants": list(LANGUAGES), "extensions": ["cs", "fs", "vb"], "tasks": list(TASKS), "contexts": ["targetFrameworks"]}, "original denominator omitted")
    provisioning = runpy.run_path(str(repo / "scripts/ci/provision-dotnet-qualification-tools.py"))
    enrollment = record["enrollment"]
    require(enrollment["schema"] == "legion-dotnet-sdk-enrollment/1" and enrollment["sdkVersion"] == provisioning["SDK"] and enrollment["runtimeVersion"] == provisioning["RUNTIME"] and "shared/Microsoft.NETCore.App/8.0.32/libcoreclr.dylib" in enrollment["sdkFiles"], "enrollment schema/SDK/runtime differs")
    sdk = enrollment["sdkProvenance"]
    require(sdk["metadataUrl"] == provisioning["METADATA"] and sdk["archiveUrl"] == provisioning["SDK_URL"] and sdk["archiveSha512"] == provisioning["SDK_SHA512"] and sdk["rid"] == "osx-arm64", "official SDK pins differ")
    for files, sha, root in (("sdkFiles", "sdkDigest", "sdkRoot"), ("packageFiles", "packagesDigest", "packagesRoot")):
        same(record[files], enrollment[files], "closure file set differs")
        require(enrollment[sha] == digest(encoded(enrollment[files])) and enrollment[files], "closure digest incomplete")
        if live:
            same(live_tree(Path(enrollment[root])), enrollment[files], "live enrolled closure changed")
    analyzer = enrollment["fsharpAnalyzer"]
    require(analyzer["id"] == "dotnet-fsharplint" and analyzer["version"] == provisioning["FSHARP_VERSION"] and analyzer["archiveSha512"] == provisioning["FSHARP_HASH"] and analyzer["sourceCommit"] == provisioning["FSHARP_COMMIT"] and analyzer["catalogUrl"] == provisioning["FSHARP_CATALOG"] and analyzer["digest"] == digest(encoded(analyzer["files"])) and "tools/net8.0/any/dotnet-fsharplint.dll" in analyzer["files"], "F# analyzer published closure differs")
    if live:
        same(live_tree(Path(analyzer["root"])), analyzer["files"], "live F# analyzer changed")
    cases = record["cases"]
    require(len(cases) == 33 and {(c["language"], c["control"]) for c in cases} == {(l, c) for l in LANGUAGES for c in CONTROLS}, "original matrix/control denominator incomplete")
    for case in cases:
        language, control = case["language"], case["control"]
        require(case["matched"] is True and case["provider"] == ID and case["caseId"] == "dotnet-" + language + "-" + control, "fixture identity differs")
        sources = {p: byte_array(b) for p, b in case["fixtureSources"].items()}
        same(case["fixtureDigests"], {p: digest(b) for p, b in sources.items()}, "fixture source bytes differ")
        for config in ("global.json", ".editorconfig", "fsharplint.json", language + "/packages.lock.json"):
            require(digest(sources[config]) == enrollment["fixtureFiles"][config], "frozen provisioned config/lock differs")
        rule_config = parsed(sources["fsharplint.json"])
        def enabled(value, prefix=""):
            found = []
            if isinstance(value, dict):
                for key, item in value.items():
                    if key == "enabled" and item is True:
                        found.append(prefix)
                    else:
                        found += enabled(item, prefix + ("." if prefix else "") + key)
            elif isinstance(value, list):
                for item in value:
                    found += enabled(item, prefix)
            return found
        same(enabled(rule_config), ["redundantNewKeyword"], "fixture did not freeze exact F# rule scope")
        extension, source_extension, answer, tests = provisioning["SOURCES"][language]
        same(sorted(sources), sorted(["global.json", ".editorconfig", "fsharplint.json", language + "/packages.lock.json", language + "/Fixture." + extension, language + "/Answer." + source_extension, language + "/Tests." + source_extension]), "fixture inventory scope changed")
        require(sources[language + "/Fixture." + extension].decode() == provisioning["project"](extension).replace("net8.0", "net9.0" if control == "unsupported-framework" else "net8.0").replace("</Project>", '<Import Project="/tmp/unfrozen.targets" /></Project>' if control == "unsupported-import" else "</Project>"), "actual fixture project differs")
        if control == "positive" and language == "fsharp":
            tests = tests.replace("Answer().Double(2)", "(new Answer()).Double(2)")
        if control != "positive":
            if language == "csharp":
                answer, tests = answer.replace("public int Double", "public static int Double"), tests.replace("new Answer().Double", "Answer.Double")
            if language == "visualBasic":
                answer, tests = answer.replace("Public Function DoubleValue", "Public Shared Function DoubleValue"), tests.replace("New Answer().DoubleValue", "Answer.DoubleValue")
        if control == "test-failure":
            tests = tests.replace("IsTrue(4 =", "IsTrue(5 =") if language == "fsharp" else tests.replace("AreEqual(4,", "AreEqual(5,")
        if control == "malformed":
            answer += "\nTHIS IS INVALID SOURCE !!!\n"
        require(sources[language + "/Answer." + source_extension].decode() == answer and sources[language + "/Tests." + source_extension].decode() == tests, "planted known-answer source differs")
        result, executions = case["nativeResult"], case["sdkExecutions"]
        accounting(case, sources, language, extension, source_extension)
        native = result["details"]["nativeProducer"]["toolReceipts"]
        seen = []
        streams = {}
        for row in executions:
            task, out, err = execution(row, case, enrollment, live)
            seen.append(task)
            streams[task] = out + "\n" + err
            retained = next(r for r in native if r["receiptId"] == row["executionReceipt"]["receiptId"])
            same(retained["sdkReceipt"], row["executionReceipt"], "native result replaced actual SDK receipt")
            if task == "analyzer" and language == "fsharp":
                scope = retained["dotnetAnalyzerScope"]
                require(scope["kind"] == "fsharp-file-rule-analysis" and scope["files"] == ["fsharp/Answer.fs", "fsharp/Tests.fs"] and scope["roslynParity"] is False, "F# declared file/rule scope differs")
                same(scope["unsupportedCoverage"], [{"kind": "fsharp-project-type-analysis-unmeasured"}, {"kind": "fsharp-cross-file-rule-coverage-unmeasured"}], "F# unmeasured scope gaps were erased")
            snapshots = retained["nativeInputSnapshots"]
            binding = snapshots["before"]
            scratch = absolute(case["policyDefinition"]["scratch"])
            require(scratch.parts[-3:] == ("dotnet-retained", "cases", case["caseId"]), "native retained case path differs")
            require(binding["stageRoot"] == str(scratch / "cache/dotnet-source")
                    and binding["sourceRoot"] == str(scratch.parents[2] / "dotnet-fixture-sources" / case["caseId"] / "source"), "native source/stage paths detached from retained case")
            same(binding["sourceContents"], case["fixtureSources"], "retained production source context differs")
            same(binding["sourceFiles"], case["fixtureDigests"], "retained frozen source hashes differ")
            same(binding["enrollment"], enrollment, "actual project used different SDK/package/analyzer enrollment")
            require(binding["enrollmentDigest"] == record["enrollmentDigest"] and binding["offlineConfigDigest"] == digest(b"<configuration><packageSources><clear /></packageSources><fallbackPackageFolders><clear /></fallbackPackageFolders><disabledPackageSources><clear /></disabledPackageSources></configuration>\n"), "restore config/enrollment binding differs")
            if not control.endswith("-drift"):
                require(snapshots["unchanged"] is True and snapshots["afterError"] is None, "frozen closure changed during SDK execution")
                same(snapshots["before"], snapshots["after"], "pre/post closure differs")
        if control in ("positive", "nonempty-clean", "test-failure", "malformed", "rejected-admission"):
            same(seen, list(TASKS), "an original task was omitted/reordered")
        elif control in ("missing-tool", "unsupported-framework", "unsupported-import"):
            require(not seen and result["complete"] is False, "unsupported/missing input became clean")
        else:
            same(seen, ["restore"], "drift did not stop subsequent SDK commands")
            require(case["driftBefore"] != case["driftObserved"] and result["complete"] is False and native[0]["nativeInputSnapshots"]["afterError"], "real closure drift was not detected")
        if control in ("positive", "nonempty-clean"):
            require(result["complete"] is True and all(t["status"] == "pass" for t in result["details"]["nativeAnalysis"]["toolEvidence"]), "baseline task coverage incomplete")
            if language == "fsharp":
                stage = absolute(case["policyDefinition"]["scratch"]) / "cache/dotnet-source"
                text = streams["analyzer"]
                require("Running FSharpLint with " in text and text.count("========== Summary: ") == 1 and len(re.findall(r"========== Finished: [0-9]+ warnings ==========", text)) == 2, "actual F# file analysis completion missing")
                for source in ("fsharp/Answer.fs", "fsharp/Tests.fs"):
                    require(text.count("========== Linting " + str(stage / source) + " ==========") == 1, "actual F# source file omitted")
            else:
                require("Microsoft.CodeAnalysis.NetAnalyzers" in streams["analyzer"], "actual Roslyn execution report missing")
            standard_results(native, True)
            if control == "positive":
                positive_finding(case, sources, streams["analyzer"])
            else:
                require(result["findings"] == [], "nonempty clean fixture produced findings")
                boundaries = case["boundaryControls"]
                fields = ("args", "cwd", "provider", "plan", "policy", "task", "digest", "environment", "allowlist", "version", "timeout", "output", "accepted", "shell", "origin", "sandbox")
                require(len(boundaries) == 17 and {b["control"] for b in boundaries} == {"request-mutation-" + f for f in fields} | {"absent-sandbox"}, "request/sandbox controls omitted")
                for b in boundaries:
                    expected_request = parsed(encoded(executions[0]["request"]))
                    expected_policy = parsed(encoded(case["policyDefinition"]))
                    field = b["control"].removeprefix("request-mutation-")
                    if field in ("args", "version"):
                        expected_request["args" if field == "args" else "versionArgs"].append("--unbound")
                    elif field in ("cwd", "plan", "policy"):
                        expected_request[{"cwd": "cwd", "plan": "planId", "policy": "policyId"}[field]] += "/unbound" if field == "cwd" else "0"
                    elif field == "provider": expected_request["providerId"] = "code.go"
                    elif field == "task": expected_request["taskId"] = "unbound"
                    elif field == "digest": expected_request["expectedDigest"] = "sha256:unbound"
                    elif field == "environment": expected_request["environment"]["UNBOUND"] = "1"
                    elif field == "allowlist": expected_request["environmentAllowlist"] = sorted(expected_request["environmentAllowlist"] + ["UNBOUND"])
                    elif field == "timeout": expected_request["timeoutMs"] += 1
                    elif field == "output": expected_request["stdoutLimit"] += 1
                    elif field == "accepted": expected_request["acceptedExitCodes"] = sorted(expected_request["acceptedExitCodes"] + [42])
                    elif field == "shell": expected_request["shell"] = True
                    elif field == "origin": expected_request["origin"] = "System"
                    elif field == "sandbox": expected_request["sandbox"]["network"] = False
                    else:
                        expected_request["sandbox"] = None
                        expected_policy["absentSandboxControl"] = True
                        for definition in expected_policy["requests"]:
                            definition["sandbox"] = None
                    same(b["request"], expected_request, "boundary control did not mutate exact source request")
                    same(b["policyDefinition"], expected_policy, "boundary control changed admission definition")
                    r = b["executionReceipt"]
                    require(r["requestId"] == expected_request["requestId"] and r["providerId"] == expected_request["providerId"] and r["taskId"] == expected_request["taskId"], "boundary receipt request binding differs")
                    require(b["matched"] is True and r["processTree"]["started"] is False and r["complete"] is False, "boundary refusal launched process")
                    if b["control"] == "request-mutation-shell":
                        require(r["policy"] is None and "shell execution is forbidden" in json.dumps(r["gaps"]), "shell validator refusal differs")
                    else:
                        require(r["policy"]["allowed"] is (b["control"] == "absent-sandbox"), "boundary policy decision differs")
                    require(r["state"] == ("sandbox_missing" if b["control"] == "absent-sandbox" else "unauthorized_effect"), "boundary outcome differs")
        if control == "test-failure":
            require(result["complete"] is False and executions[-1]["executionReceipt"]["exitCode"] != 0, "deliberate assertion failure became successful")
            standard_results(native, False)
        if control == "malformed":
            require(result["complete"] is False and executions[1]["executionReceipt"]["exitCode"] != 0, "malformed source became successful")
        if control == "rejected-admission":
            require(result["complete"] is False, "default owner denial became successful")
        if control != "source-drift":
            same(case["sourceAfter"], case["fixtureSources"], "audit mutated original project")
    same(record["metrics"], {"cases": 33, "matched": 33, "mismatched": 0, "wholeProviderQualified": False, "boundedSdkAccuracyQualified": True}, "qualification scope/metrics differ")
    return {"provider": ID, "schema": record["schema"], "qualificationDigest": record["qualificationDigest"], "cases": 33, "qualificationEligible": True, "productionQualification": False, "claimScope": "known-answer-fixture-cases", "modelCalls": 0, "variants": list(LANGUAGES), "tasks": list(TASKS), "requestBoundaryControls": 51, "boundedSdkAccuracyQualified": True, "wholeProviderQualified": False, "productionAdmission": False}


def validate_record(repository_root, row, live=False, enrollment=None):
    if enrollment is not None:
        same(row["enrollment"], enrollment, "retained enrollment differs from executed inputs")
    return validate(Path(repository_root), row, live)


def artifact_locator(row, raw):
    return {"schema": "legion-dotnet-code-command-sdk-artifact/1", "provider": ID, "file": "code_dotnet.json", "digest": digest(raw), "bytes": len(raw), "qualificationDigest": row["qualificationDigest"], "qualificationEligible": True, "productionQualification": False}


def child_record(execution_path, stdout_path, stderr_path, record_path):
    execution = parsed(Path(execution_path).read_bytes())
    require(set(execution) == {"schema", "productionQualification", "status", "stdout", "stderr"} and execution["schema"] == "legion-dotnet-code-command-child-execution/1" and execution["productionQualification"] is False, "child execution schema differs")
    same(execution["status"], {"success": True, "exitCode": 0, "signal": None}, "actual .NET control harness failed")
    streams = []
    for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        path = Path(path)
        require(path.is_file() and not path.is_symlink(), "child stream missing/unsafe")
        raw = path.read_bytes()
        same(execution[name], {"file": "child." + name + ".log", "bytes": len(raw), "sha256": digest(raw)}, "actual child output differs")
        streams.append(raw)
    path = Path(record_path)
    require(path.is_file() and not path.is_symlink(), "original SDK record missing/unsafe")
    raw = path.read_bytes()
    row = parsed(raw)
    marker = b"DOTNET_CODE_COMMAND_SDK_ACCURACY_ARTIFACT "
    locators = [parsed(line.split(marker, 1)[1]) for line in streams[0].splitlines() if marker in line]
    same(locators, [artifact_locator(row, raw)], "actual child did not emit exact SDK artifact locator")
    text = streams[0].decode()
    require(re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", text) == [("1", "0", "0")] and len(re.findall(r"\btest native_providers::code::tools::dotnet_sdk_accuracy::original_dotnet_sdk_contract_has_real_language_task_and_boundary_controls \.\.\.", text)) == 1, "named native SDK test did not execute exactly once")
    return row


def validate_retained(root, row, paths):
    require(set(paths) == {"childExecution", "childStdout", "childStderr", "dotnetEnrollment", "providerRecord"}, "retained SDK metadata paths differ")
    observed = child_record(paths["childExecution"], paths["childStdout"], paths["childStderr"], paths["providerRecord"])
    same(observed, row, "indexed record differs from original child artifact")
    raw = Path(paths["dotnetEnrollment"]).read_bytes()
    require(row["enrollmentDigest"] == digest(raw), "original enrollment bytes changed")
    return validate_record(root, row, live=False, enrollment=parsed(raw))


def validate_records(root, receipts, live=True):
    receipts = Path(receipts)
    require(receipts.is_dir() and not receipts.is_symlink(), "retained SDK evidence missing/unsafe")
    require({p.name for p in receipts.glob("code_*.json")} == {"code_dotnet.json"}, "original SDK record inventory differs")
    row = child_record(receipts / "child-execution.json", receipts / "child.stdout.log", receipts / "child.stderr.log", receipts / "code_dotnet.json")
    raw = (receipts / "dotnet-sdk-enrollment.json").read_bytes()
    require(row["enrollmentDigest"] == digest(raw), "original enrollment bytes differ")
    return {"records": [validate_record(root, row, live=live, enrollment=parsed(raw))], "modelCalls": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", "--repo", dest="repo", type=Path, default=Path(__file__).resolve().parents[2])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--record", type=Path)
    group.add_argument("--receipts", type=Path)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    result = validate_records(args.repo, args.receipts, live=True) if args.receipts else validate_record(args.repo, parsed(args.record.read_bytes()), args.live)
    print("DOTNET_CODE_COMMAND_SDK_ACCURACY_SUMMARY " + json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
