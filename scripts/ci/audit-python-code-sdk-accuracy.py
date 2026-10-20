#!/usr/bin/env python3
"""Replay original Python SDK known-answer artifacts; never grant production admission."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import runpy

COMMON = "scripts/ci/audit-code-sdk-accuracy.py"
BOOTSTRAP = "scripts/ci/audit-python-sdk-bootstrap.py"
BOOTSTRAP_REVIEWED_DIGEST = "sha256:2a1d1c950d7b57b101801e47ede71562d0e68a0bd6b8f55422a40559305d6511"
HARNESS = "engine/crates/legion-audit/tests/real_python_code_command_accuracy.rs"
FIXTURES = "scripts/ci/fixtures/audit-code-python-sdk-accuracy"
POLICY = "legion-real-python-code-command-fixture-v1"
PROVIDER = "code.python"
CONTROLS = ("nonempty-clean", "lint-positive", "type-positive", "compile-error", "test-failure", "build-error", "invalid-wheel", "missing-backend", "malformed-config", "source-drift", "missing-tool", "rejected-admission", "absent-sandbox")
TASKS = ("compile", "lint", "type", "test", "package", "package")
# Reuse reviewed canonical JSON, safe-path, raw-artifact & original CONFIG readers.
_shared = runpy.run_path(str(Path(__file__).resolve().parents[2] / COMMON))
for _name in ("require", "keys", "encoded", "digest", "is_digest", "same", "receipt_fields", "parsed", "source_file", "absolute", "artifact", "required_contract"):
    globals()[_name] = _shared[_name]
RECEIPT_FIELDS = _shared["RECEIPT_FIELDS"]
SOURCE_ROOTS = ["engine/crates/" + c + "/src" for c in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")] + ["src/registry/rules", "src/registry/controls", FIXTURES]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HARNESS, BOOTSTRAP, "scripts/ci/provision-python-qualification-tools.py", "scripts/ci/audit-pip-audit-provider-accuracy.py", "scripts/ci/python-tool-locks/code-python-sdk-macos-arm64-cp314.json", "scripts/ci/python-tool-locks/code-python-sdk-macos-arm64-cp314.txt"] + ["engine/crates/" + c + "/Cargo.toml" for c in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")]

def generated_session_provenance(relative):
    return re.fullmatch(
        r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json",
        relative,
    ) is not None


def source_files(root):
    paths = set(SOURCE_FILES)
    for relative in SOURCE_ROOTS:
        p = Path(root) / relative
        require(p.is_dir() and not p.is_symlink(), "source closure root missing")
        for item in p.rglob("*"):
            require(not item.is_symlink(), "source closure symlink")
            if item.is_file():
                if generated_session_provenance(item.relative_to(root).as_posix()):
                    continue
                paths.add(item.relative_to(root).as_posix())
    return sorted(paths)

def fixture(root, control):
    name = "nonempty-clean" if control in ("missing-tool", "rejected-admission", "absent-sandbox", "source-drift") else control
    p = Path(root) / FIXTURES / name
    require(p.is_dir() and not p.is_symlink(), "fixture source missing")
    result = {}
    for item in sorted(p.rglob("*")):
        require(not item.is_symlink(), "fixture symlink")
        if item.is_file(): result[item.relative_to(p).as_posix()] = item.read_text()
    require(result, "empty known-answer fixture")
    return result

def literal(root, relative, name):
    text = source_file(root, relative).read_text()
    prefix = 'const ' + name + ': &str = r#"'
    require(text.count(prefix) == 1, "owned command literal changed")
    return text.split(prefix, 1)[1].split('"#;', 1)[0]

def command_definitions(root, policy, files, scratch, enrollment):
    stage = scratch / "cache/python-sdk/source"
    original = absolute(policy["originalRoot"])
    hashes = {p: digest(t.encode()) for p, t in files.items()}
    source_digest = digest(json.dumps({"schema": "legion-python-frozen-inputs/1", "originalRoot": str(original), "files": hashes}, ensure_ascii=False, separators=(",", ":")).encode())
    prefix = ["-f", policy["profile"]["path"], "--"]
    def spec(task, args):
        tool = {"lint": "ruff", "type": "mypy", "test": "pytest"}.get(task, "python3")
        accepted = [0, 1] if task in ("compile", "lint", "type") else [0]
        return {"task": task, "args": args, "versionArgs": prefix + [enrollment["tools"][tool]["path"], "--version"], "acceptedExitCodes": accepted}
    selected = sorted(p for p in files if p.endswith(".py"))
    commands = [
        spec("compile", ["-I", "-B", "-c", literal(root, "engine/crates/legion-audit/src/native_providers/code/tools.rs", "PY_COMPILE_SCRIPT"), str(scratch / "tmp/py-compile-files.txt"), str(scratch / "cache/py-compile"), encoded(selected).decode()]),
        spec("lint", ["check", "--no-cache", "--output-format", "json", "."]),
        spec("type", ["--no-incremental", "--cache-dir", str(scratch / "cache/mypy"), "--no-color-output", "--show-error-codes", "--no-pretty", "."]),
        spec("test", ["--assert=plain", "-o", "cache_dir=" + str(scratch / "cache/pytest"), "--basetemp", str(scratch / "tmp/pytest")]),
        spec("package", ["-I", "-B", "-m", "build", "--wheel", "--no-isolation", "--outdir", str(scratch / "cache/python-wheels-0"), str(stage)]),
        spec("package", ["-I", "-B", "-c", literal(root, "engine/crates/legion-audit/src/native_providers/code/python_commands.rs", "WHEEL_INSPECT"), str(scratch / "cache/python-wheels-0"), "fixture-pkg", "1.0.0", source_digest]),
    ]
    same(policy["commands"], commands, "source-owned original argv/probes/accepted exits differ")
    require(policy["frozenSourceDigest"] == source_digest and policy["cwd"] == str(stage), "frozen staging source identity differs")
    return commands, hashes, source_digest

def environment(policy, scratch, original, enrollment):
    base = {"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"}
    expected = {"PATH": enrollment["environment"]["LEGION_PYTHON_SDK_BIN_DIR"], "HOME": str(original.parent.parent / "home")}
    for name, rel in (("TMPDIR", "tmp"), ("TEMP", "tmp"), ("TMP", "tmp"), ("XDG_CACHE_HOME", "cache/xdg"), ("CARGO_TARGET_DIR", "cache/cargo-target"), ("npm_config_cache", "cache/npm"), ("RUFF_CACHE_DIR", "cache/ruff"), ("MYPY_CACHE_DIR", "cache/mypy"), ("PYTHONPYCACHEPREFIX", "cache/pycache"), ("GOCACHE", "cache/go-build")):
        expected[name] = str(scratch / rel)
    expected.update(PYTHONNOUSERSITE="1", GIT_CONFIG_NOSYSTEM="1", PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1", CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never", PYTHONSAFEPATH="1")
    same(policy["environment"], expected, "isolated SDK child environment differs")
    same(policy["environmentAllowlist"], sorted(base | set(expected)), "SDK child environment allowlist differs")
    return expected

def sdk(item, policy, control, plan, scratch, enrollment, commands, live):
    keys(item, ("request", "executionReceipt", "stdout", "stderr"))
    req, r = item["request"], item["executionReceipt"]
    receipt_fields(r, owner_projection=True)
    keys(req, ("schemaVersion", "requestId", "providerId", "planId", "policyId", "taskId", "executable", "args", "cwd", "origin", "shell", "expectedDigest", "acceptedExitCodes", "versionArgs", "skipVersionProbe", "versionRequirement", "environment", "environmentAllowlist", "sensitiveArgumentIndexes", "sensitiveEnvironmentNames", "requiresNetworkSandbox", "sandbox", "timeoutMs", "stdoutLimit", "stderrLimit"))
    task = req["taskId"]
    require(task in TASKS and re.fullmatch(r"legion-audit/[0-9a-f]{64}", req["requestId"] or ""), "actual SDK identity differs")
    tool = {"lint": "ruff", "type": "mypy", "test": "pytest"}.get(task, "python3")
    prefix = ["-f", policy["profile"]["path"], "--", enrollment["tools"][tool]["path"]]
    matching = [c for c in commands if c["task"] == task and req["args"] == prefix + c["args"]]
    require(len(matching) == 1, "SDK command is outside exact source-owned contract")
    command = matching[0]
    expected = dict(req, schemaVersion=1, providerId=PROVIDER, planId=plan, policyId="audit", executable=policy["wrapper"]["path"], args=prefix + command["args"], cwd=policy["cwd"], origin="TargetProject", shell=False, expectedDigest=policy["wrapper"]["digest"], acceptedExitCodes=command["acceptedExitCodes"], versionArgs=command["versionArgs"], skipVersionProbe=False, versionRequirement=None, environment=policy["environment"], environmentAllowlist=policy["environmentAllowlist"], sensitiveArgumentIndexes=[], sensitiveEnvironmentNames=[], requiresNetworkSandbox=True, sandbox=None if control == "absent-sandbox" else {"id": policy["profile"]["receiptId"], "network": True, "filesystemScope": policy["originalRoot"]}, timeoutMs=120000, stdoutLimit=33554432, stderrLimit=33554432)
    same(req, expected, "actual SDK argv/cwd/env/digest/sandbox/bounds changed")
    require(r["schemaVersion"] == 1 and r["requestId"] == req["requestId"] and r["receiptId"] == "receipt:" + req["requestId"] and r["providerId"] == PROVIDER and r["planId"] == plan and r["taskId"] == task and r["cwd"] == req["cwd"], "SDK receipt request binding differs")
    same(r["command"], {"executable": req["executable"], "args": req["args"], "environmentNames": sorted(req["environment"]), "redactedArgumentIndexes": [], "redactedEnvironmentNames": []}, "SDK launched command differs")
    same(r["environmentNames"], sorted(req["environment"]), "SDK launched environment differs")
    p = r["policy"]
    keys(p, ("id", "version", "digest", "allowed", "reason"))
    require(r["policyId"] == p["id"] and p["version"] == 1, "SDK actual policy identity differs")
    rejected, absent = control == "rejected-admission", control == "absent-sandbox"
    if rejected:
        same(p, {"id": "audit-native-owner-admission-v1", "version": 1, "allowed": False, "reason": "native-owner-admission-unavailable", "digest": digest(encoded({"externalProcesses": "owner-admission-required", "admissionStatus": "unavailable", "effectiveMode": "deny-external"}))}, "actual production owner admission denial missing")
    else:
        same(p, {"id": POLICY, "version": 1, "allowed": True, "reason": "exact constructed Python SDK fixture request", "digest": digest(encoded(policy))}, "constructed exact SDK admission binding differs")
    same(r["parser"], {"attempted": False, "succeeded": False, "error": None}, "raw SDK receipt reinterpreted")
    same(r["sandbox"], {"required": True, "receiptId": None if absent else policy["profile"]["receiptId"], "networkEnabled": not absent}, "SDK sandbox receipt differs")
    keys(r["timing"], ("startedAtMs", "completedAtMs", "durationMs"))
    require(all(type(v) is int and v >= 0 for v in r["timing"].values()), "SDK timing malformed")
    if rejected or absent:
        require(r["state"] == ("unauthorized_effect" if rejected else "sandbox_missing") and r["complete"] is False and r["exitCode"] is r["signal"] is None and r["gaps"], "actual SDK refusal became execution/clean")
        if rejected:
            require(r["executable"] is None, "owner-admission refusal resolved an executable")
        else:
            e = r["executable"]
            require(e["canonicalPath"] == e["requestedPath"] == policy["wrapper"]["path"] and e["digest"] == policy["wrapper"]["digest"] and e["digestState"] == "sealed", "sandbox refusal lost resolved wrapper identity")
            same(e["version"], {"args": [], "output": None, "exitCode": None, "qualified": False, "skippedByPolicy": False}, "sandbox refusal probed executable version")
            require(r["gaps"] == ["network sandbox receipt is required"], "sandbox refusal gap differs")
        same(r["processTree"], {"started": False, "terminated": False, "hardKilled": False, "reaped": False, "detail": None}, "SDK refusal launched process")
        same(r["timing"], {"startedAtMs": 0, "completedAtMs": 0, "durationMs": 0}, "SDK refusal launched timed process")
    else:
        e = r["executable"]
        require(e["canonicalPath"] == e["requestedPath"] == policy["wrapper"]["path"] and e["digest"] == policy["wrapper"]["digest"] and e["digestState"] == "sealed", "SDK wrapper identity differs")
        version = e["version"]
        require(version["args"] == command["versionArgs"] and version["skippedByPolicy"] is False, "actual tool probe bypassed")
        if control == "malformed-config" and r["state"] == "unsealed_executable":
            require(version["qualified"] is False and type(version["exitCode"]) is int and version["exitCode"] != 0 and version["output"] and r["complete"] is False and r["gaps"], "config failed probe was falsely clean")
        else:
            wanted = enrollment["tools"][tool]["version"]
            require(version["qualified"] is True and version["exitCode"] == 0 and re.search(r"(?<![0-9.])" + re.escape(wanted) + r"(?![0-9.])", version["output"] or ""), "actual pinned tool version unproven")
            good = r["exitCode"] in req["acceptedExitCodes"]
            require(r["state"] == ("completed" if good else "failed") and r["complete"] is good, "process failure promoted to success")
            tree = r["processTree"]
            require(tree["started"] is tree["terminated"] is tree["reaped"] is True and tree["hardKilled"] is False and r["signal"] is None, "native process lifecycle incomplete")
            require(r["timing"]["startedAtMs"] > 0 and r["timing"]["completedAtMs"] >= r["timing"]["startedAtMs"] and r["timing"]["durationMs"] == r["timing"]["completedAtMs"] - r["timing"]["startedAtMs"], "native process timing inconsistent")
    out = artifact(r["stdout"], item["stdout"], scratch, live)
    err = artifact(r["stderr"], item["stderr"], scratch, live)
    return out, err

def mutations(case, scratch, live):
    controls = case.get("requestMutationControls")
    require(isinstance(controls, list) and [c["mutatedField"] for c in controls] == ["args", "cwd", "executable", "planId"], "four same-policy request mutation controls required")
    source = next(r["request"] for r in case["sdkExecutions"] if r["request"]["taskId"] == "compile")
    policy = case["policyDefinition"]
    for c in controls:
        field = c["mutatedField"]
        keys(c, ("control", "scope", "qualificationEligible", "sourceRequest", "baselineRequest", "mutatedField", "policyDefinition", "policyDecisions", "sdkExecutions", "matched"))
        require(c["control"] == "request-mutation-" + field and c["scope"] == "sdk-exact-policy-boundary" and c["qualificationEligible"] is False and c["matched"] is True, "mutation identity/status differs")
        same(c["sourceRequest"], source, "mutation source is not original successful request")
        same(c["policyDefinition"], policy, "mutation changed authorizer definition")
        baseline = dict(source, requestId="legion-audit/" + digest((source["requestId"] + ":mutation:" + field).encode())[7:])
        same(c["baselineRequest"], baseline, "mutation changed admitted baseline")
        wanted = dict(baseline)
        wanted[field] = baseline["args"] + ["--outside-fixture-command"] if field == "args" else str(absolute(policy["originalRoot"]).parent) if field == "cwd" else policy["toolIdentities"]["python3"][0] if field == "executable" else "different-frozen-plan"
        require(len(c["sdkExecutions"]) == 1, "mutation must retain one actual refusal")
        row = c["sdkExecutions"][0]
        same(row["request"], wanted, "mutation did not change exactly one bound field")
        same(c["policyDecisions"], [{"requestId": wanted["requestId"], "taskId": wanted["taskId"], "allowed": False, "request": wanted}], "same scoped policy did not refuse mutation")
        r = row["executionReceipt"]
        keys(r, RECEIPT_FIELDS)
        require(r["schemaVersion"] == 1 and r["receiptId"] == "receipt:" + wanted["requestId"] and r["requestId"] == wanted["requestId"] and r["providerId"] == PROVIDER and r["planId"] == wanted["planId"] and r["taskId"] == "compile" and r["cwd"] == wanted["cwd"] and r["policyId"] == POLICY and r["state"] == "unauthorized_effect" and r["complete"] is False and r["executable"] is r["exitCode"] is r["signal"] is r["stdout"] is r["stderr"] is row["stdout"] is row["stderr"] is None and r["gaps"], "mutation refusal launched process or invented receipt")
        same(r["policy"], {"id": POLICY, "version": 1, "digest": digest(encoded(policy)), "allowed": False, "reason": "outside exact constructed Python SDK fixture contract"}, "mutation used different policy authority")
        same(r["processTree"], {"started": False, "terminated": False, "hardKilled": False, "reaped": False, "detail": None}, "mutation launched process")
        same(r["timing"], {"startedAtMs": 0, "completedAtMs": 0, "durationMs": 0}, "mutation launched timed process")
        same(r["parser"], {"attempted": False, "succeeded": False, "error": None}, "mutation invoked parser")
        same(r["command"], {"executable": wanted["executable"], "args": wanted["args"], "environmentNames": sorted(wanted["environment"]), "redactedArgumentIndexes": [], "redactedEnvironmentNames": []}, "mutation original command lost")
        same(r["environmentNames"], sorted(wanted["environment"]), "mutation environment changed")
        same(r["sandbox"], {"required": True, "receiptId": wanted["sandbox"]["id"], "networkEnabled": True}, "mutation sandbox changed")
        if live: same(parsed(Path(scratch, "mutations", field, "sdk-execution-0.json").read_bytes()), row, "actual mutation evidence changed")

def frozen_denominator(case, spec, entries):
    # InventoryDenominator uses InventoryEnvelope.digest directly for always.
    # validate_case independently seals inventory & entries before this boundary.
    frozen = case["frozenProvider"]
    same(spec["selector"], {"op": "always"}, "original Python always selector changed")
    same(frozen["configuration"]["selector"], spec["selector"], "frozen Python selector changed")
    require(is_digest(case["planDigest"]) and frozen["id"] == PROVIDER and frozen["version"] == spec["providerVersion"]
            and frozen["configuration"]["denominatorCount"] == len(entries)
            and frozen["configuration"]["denominatorDigest"] == case["inventory"]["digest"], "original provider denominator changed")

def validate_case(root, case, enrollment, live):
    control = case["control"]
    fields = {"caseId", "control", "provider", "scope", "fixtureFiles", "fixtureSources", "inventory", "planDigest", "frozenProvider", "nativeResult", "policyDefinition", "policyDecisions", "sdkExecutions", "runtimeBefore", "runtimeAfter", "matched"}
    if control == "nonempty-clean": fields.add("requestMutationControls")
    keys(case, fields)
    require(control in CONTROLS and case["caseId"] == "code-python-" + control and case["provider"] == PROVIDER and case["matched"] is True and case["scope"] == ("sdk-boundary-control" if control == "absent-sandbox" else "native-provider-known-answer-fixture"), "case identity/status differs")
    files = fixture(root, control)
    hashes = {p: digest(t.encode()) for p, t in files.items()}
    same(case["fixtureFiles"], files, "original fixture bytes differ")
    same(case["fixtureSources"], hashes, "frozen fixture source digests differ")
    inv = case["inventory"]
    entries = [{"path": p, "symbols": [], "dependencies": [], "packageScripts": [], "sourceFile": p.endswith(".py"), "digest": hashes[p]} for p in sorted(files)]
    same(inv["entries"], entries, "frozen inventory dropped/added source/context siblings")
    require(inv["schemaVersion"] == 1 and inv["repositoryId"] == case["caseId"] and inv["generation"] == "filesystem:" + digest(encoded(entries)) and inv["digest"] == digest(encoded([1, case["caseId"], inv["generation"], entries])), "inventory identity differs")
    spec = next(s for s in parsed(source_file(root, "src/registry/providers.json").read_bytes())["providers"] if s["id"] == PROVIDER)
    frozen_denominator(case, spec, entries)
    policy = case["policyDefinition"]
    keys(policy, ("id", "version", "scope", "provider", "planDigest", "originalRoot", "cwd", "frozenSourceDigest", "toolIdentities", "wrapper", "profile", "commands", "environment", "environmentAllowlist", "absentSandboxControl", "timeoutMs", "stdoutLimit", "stderrLimit"))
    original = absolute(policy["originalRoot"])
    scratch = absolute(policy["profile"]["path"]).parent.parent
    require(original.name == "source" and original.parent.name == case["caseId"] and scratch.name == case["caseId"] and scratch.parent.name == "cases" and not (original == scratch or original in scratch.parents or scratch in original.parents), "private original/scratch boundaries differ")
    require(policy["id"] == POLICY and policy["version"] == 1 and policy["provider"] == PROVIDER and policy["planDigest"] == case["planDigest"] and policy["scope"] == "exact constructed Python SDK fixtures; no production owner admission" and policy["absentSandboxControl"] is (control == "absent-sandbox") and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 33554432, "constructed policy scope/bounds differ")
    tool_identities = {name: [enrollment["tools"][name]["path"], enrollment["tools"][name]["digest"]] for name in ("python3", "ruff", "mypy", "pytest")}
    same(policy["toolIdentities"], tool_identities, "executed tools differ from enrolled closed runtime")
    require(policy["wrapper"]["path"] == "/usr/bin/sandbox-exec" and is_digest(policy["wrapper"]["digest"]), "actual native sandbox identity missing")
    if live: require(digest(Path(policy["wrapper"]["path"]).read_bytes()) == policy["wrapper"]["digest"], "live sandbox changed")
    escaped = str(original).replace('\\', '\\\\').replace('"', '\\"')
    text = '(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath "' + escaped + '"))\n(deny file-write* (subpath "' + escaped + '"))\n'
    sha = digest(text.encode())[7:]
    same(policy["profile"], {"path": str(scratch / "sandbox" / ("audit-" + sha + ".sb")), "text": text, "receiptId": "sandbox:macos:" + sha}, "network/project-write boundary changed")
    environment(policy, scratch, original, enrollment)
    commands, hashes, input_digest = command_definitions(root, policy, files, scratch, enrollment)
    expected_runtime = {"schema": "legion-python-sdk-runtime-observation/1", "runtimeDigest": enrollment["runtime"]["digest"], "fileCount": len(enrollment["runtime"]["files"]), "linkCount": len(enrollment["runtime"]["links"]), "absentCount": len(enrollment["runtime"]["absent"])}
    same(case["runtimeBefore"], expected_runtime, "before runtime closure absent")
    same(case["runtimeAfter"], expected_runtime, "after runtime drift hidden")
    rows = case["sdkExecutions"]
    expected_tasks = [] if control in ("source-drift", "missing-tool") else ["type"] if control == "absent-sandbox" else list(TASKS[:4]) if control == "malformed-config" else list(TASKS)
    require([r["request"]["taskId"] for r in rows] == expected_tasks and len({r["request"]["requestId"] for r in rows}) == len(rows), "required SDK calls missing/duplicated/reordered")
    streams = []
    for n, row in enumerate(rows):
        streams.append(sdk(row, policy, control, case["planDigest"], scratch, enrollment, commands, live))
        if live: same(parsed(Path(scratch, "sdk-execution-" + str(n) + ".json").read_bytes()), row, "original SDK artifact changed")
    decisions = [] if control in ("source-drift", "missing-tool", "rejected-admission") else [{"requestId": r["request"]["requestId"], "taskId": r["request"]["taskId"], "allowed": True, "request": r["request"]} for r in rows]
    same(case["policyDecisions"], decisions, "actual scoped authorizer decisions differ")
    native = case["nativeResult"]
    if control == "absent-sandbox": require(native is None, "SDK refusal invented provider report")
    else:
        full = control in ("nonempty-clean", "lint-positive", "type-positive")
        require(native["provider"] == PROVIDER and native["applicable"] is True and native["complete"] is False and (native["coverage_gaps"] == ["code.python:lint-scope-unproven"] if full else bool(native["coverage_gaps"])) and native["coverage"]["expected"] == len(entries), "native runtime completeness/gaps changed")
        if full: require(native["coverage"]["examined"] == len(entries), "full original denominator not examined")
        producer = native["details"]["nativeProducer"]
        require(producer["deferredCommands"] == [], "required original tool silently deferred")
        receipts = producer["toolReceipts"]
        require(len(receipts) == len(rows), "native original SDK receipts omitted")
        for receipt, row in zip(receipts, rows):
            same(receipt["sdkReceipt"], row["executionReceipt"], "native SDK evidence was reinterpreted/reissued")
            observed = {"schema": "legion-python-input-snapshot/1", "manifestDigest": input_digest, "originalRoot": str(original), "stageRoot": policy["cwd"], "originalFiles": hashes, "stagedFiles": hashes}
            same(receipt["nativeInputSnapshots"], {"before": observed, "after": observed, "afterError": None, "unchanged": True}, "frozen original/staged input drift hidden")
        find = native["details"]["findingEvidence"]
        if full:
            require(all(r["executionReceipt"]["state"] == "completed" and r["executionReceipt"]["complete"] is True for r in rows), "full known-answer case has failed SDK call")
            comp = [parsed(line) for line in streams[0][0].splitlines()]
            selected = sorted(p for p in files if p.endswith(".py"))
            same(comp, [{"done": len(selected), "files": selected}], "compiler didn't actually inspect every selected source")
            lint = parsed(streams[1][0])
            require(isinstance(lint, list), "actual Ruff JSON absent")
            if control == "lint-positive": require(any(r.get("code") == "F401" and r.get("filename") == str(absolute(policy["cwd"]) / "fixture_pkg/__init__.py") for r in lint), "actual planted lint detection absent")
            else: require(lint == [], "unexpected Ruff findings in clean scope")
            mypy = streams[2][0].decode()
            if control == "type-positive": require('fixture_pkg/__init__.py:2: error:' in mypy and '[return-value]' in mypy and re.search(r'Found 1 error in 1 file \(checked 2 source files\)', mypy), "actual planted type detection absent")
            else: require(mypy.strip() == "Success: no issues found in 2 source files", "nonempty actual type coverage unproven")
            require(re.search(r'\b1 passed\b', streams[3][0].decode()) is not None and rows[3]["executionReceipt"]["exitCode"] == 0, "real nonempty passing test missing")
            wheel = parsed(streams[5][0])
            require(wheel["schema"] == "legion-python-wheel/1" and wheel["sourceDigest"] == input_digest and wheel["name"] == "fixture-pkg" and wheel["version"] == "1.0.0" and type(wheel["bytes"]) is int and wheel["bytes"] > 0 and is_digest(wheel["digest"]) and wheel["files"]["fixture_pkg/__init__.py"] == hashes["fixture_pkg/__init__.py"], "real wheel/source identity unproven")
            require(absolute(wheel["path"]).parent == scratch / "cache/python-wheels-0" and all(is_digest(d) for d in wheel["files"].values()) and any(p.endswith(".dist-info/RECORD") for p in wheel["files"]), "actual wheel artifact/RECORD absent")
            if live: require(digest(Path(wheel["path"]).read_bytes()) == wheel["digest"] and Path(wheel["path"]).stat().st_size == wheel["bytes"], "actual wheel bytes changed")
            if control == "nonempty-clean": require(find == {} and all(r["executionReceipt"]["exitCode"] == 0 for r in rows), "nonempty clean includes findings/process failure")
            else:
                rule = "ruff:F401" if control == "lint-positive" else "mypy:return-value"
                require(any(f["ruleId"] == rule and f["path"] == "fixture_pkg/__init__.py" for f in find.values()), "native planted finding lost original identity")
        if control == "compile-error": require(any(parsed(line).get("path") == "fixture_pkg/__init__.py" for line in streams[0][0].splitlines()), "actual compiler syntax diagnostic absent")
        if control == "test-failure": require(rows[3]["executionReceipt"]["state"] == "failed" and rows[3]["executionReceipt"]["exitCode"] == 1 and b"FAILED" in streams[3][0], "real failed test not preserved")
        if control in ("build-error", "missing-backend"): require(rows[4]["executionReceipt"]["state"] == "failed" and rows[4]["executionReceipt"]["exitCode"] != 0 and (b"planted actual backend build failure" if control == "build-error" else b"legion_fixture_missing_backend") in streams[4][0] + streams[4][1], "actual backend build failure absent")
        if control == "invalid-wheel": require(rows[5]["executionReceipt"]["state"] == "failed" and rows[5]["executionReceipt"]["exitCode"] != 0 and b"wheel RECORD" in streams[5][1], "actual invalid-wheel refusal absent")
        gaps = json.dumps(native["coverage_gaps"])
        if control == "malformed-config": require("python-package-manifest-malformed" in gaps, "malformed config gap omitted")
        if control == "source-drift": require("python-frozen-digest" in gaps, "changed frozen source gap omitted")
        if control == "missing-tool": require("tool-missing" in gaps, "missing tools became clean")
    if control == "nonempty-clean": mutations(case, scratch, live)
    return {case["caseId"] + "/" + p: d for p, d in hashes.items()}

def retained_enrollment(root, record, path, live):
    raw = Path(path).read_bytes()
    same(record["enrollment"], {"file": "python-sdk-enrollment.json", "digest": digest(raw), "bytes": len(raw)}, "original enrollment bytes differ")
    value = parsed(raw)
    bootstrap_path = source_file(root, BOOTSTRAP)
    require(digest(bootstrap_path.read_bytes()) == BOOTSTRAP_REVIEWED_DIGEST, "reviewed Python bootstrap source differs")
    bootstrap = runpy.run_path(str(bootstrap_path))
    bootstrap["verify_enrollment"](root, value, live=live)
    return value

def validate_record(repository_root, row, live=False, enrollment=None):
    root = Path(repository_root).resolve()
    keys(row, ("schema", "kind", "provider", "providerVersion", "productionQualification", "qualificationEligible", "claimScope", "executionPath", "modelCalls", "admissionScope", "packageContract", "binding", "requiredContract", "executedScope", "enrollment", "runtimeBefore", "runtimeAfter", "cases", "missingControls", "metrics", "status", "qualificationDigest"))
    require(row["schema"] == "legion-python-code-command-sdk-accuracy/1" and row["kind"] == "python-code-command-sdk-constructed" and row["provider"] == PROVIDER and row["productionQualification"] is False and row["qualificationEligible"] is True and row["claimScope"] == "known-answer-fixture-cases" and row["executionPath"] == "native-sdk-frozen-plan-self-sourced-code" and type(row["modelCalls"]) is int and row["modelCalls"] == 0 and row["admissionScope"] == "explicit constructed SDK authorizer; genuine OwnerAdmissionRequired denial; no production owner-admission claim", "Python bounded SDK identity/scope differs")
    require(row["qualificationDigest"] == digest(encoded({k: v for k, v in row.items() if k != "qualificationDigest"})), "original qualification digest differs")
    require(row["packageContract"] == "python-package/v1: actual offline PEP517 wheel build against declared installed backend; actual wheel METADATA/WHEEL/RECORD validation; frozen original/staged source identity", "explicit new package/v1 contract changed")
    contract = required_contract(root, PROVIDER)
    contract.pop("coverageRequirement")
    same(contract, {"tools": ["compile", "lint", "type", "test", "package"], "extensions": ["py"], "variants": [["python", ["py"]]], "requiredContext": ["packageRoots"]}, "source Python contract changed; do not narrow")
    same(row["requiredContract"], contract, "original tool/context contract narrowed")
    same(row["executedScope"], contract["tools"], "required tool execution scope missing")
    spec = next(s for s in parsed(source_file(root, "src/registry/providers.json").read_bytes())["providers"] if s["id"] == PROVIDER)
    spec = {k: v for k, v in spec.items() if k != "benchmark"}
    require(row["providerVersion"] == spec["providerVersion"], "provider version stale")
    binding = row["binding"]
    keys(binding, ("providerSpec", "providerSpecDigest", "sources", "sourcesDigest", "fixtureSources", "fixtureSourcesDigest", "fixture"))
    sources = {p: digest(source_file(root, p).read_bytes()) for p in source_files(root)}
    same(binding["providerSpec"], spec, "source provider registration differs")
    same(binding["sources"], sources, "production/SDK/fixture/bootstrap source closure differs")
    require(binding["providerSpecDigest"] == digest(encoded(spec)) and binding["sourcesDigest"] == digest(encoded(sources)) and binding["fixture"] == HARNESS, "source closure digest differs")
    require(enrollment is not None, "actual retained managed Python/tool enrollment required")
    require([c["control"] for c in row["cases"]] == list(CONTROLS), "required control corpus missing/reordered")
    fixtures = {}
    for c in row["cases"]: fixtures.update(validate_case(root, c, enrollment, live))
    same(binding["fixtureSources"], fixtures, "full fixture denominator differs")
    require(binding["fixtureSourcesDigest"] == digest(encoded(fixtures)), "fixture corpus digest differs")
    observation = {"schema": "legion-python-sdk-runtime-observation/1", "runtimeDigest": enrollment["runtime"]["digest"], "fileCount": len(enrollment["runtime"]["files"]), "linkCount": len(enrollment["runtime"]["links"]), "absentCount": len(enrollment["runtime"]["absent"])}
    same(row["runtimeBefore"], observation, "runtime before evidence differs")
    same(row["runtimeAfter"], observation, "runtime after evidence differs")
    same(row["missingControls"], [], "mandatory qualification dependency missing")
    same(row["metrics"], {"cases": len(CONTROLS), "matched": len(CONTROLS), "mismatched": 0, "wholeProviderQualified": False, "boundedSdkAccuracyQualified": True}, "bounded accuracy promoted to arbitrary-input whole-provider proof")
    require(row["status"] == "observed-known-answer-controls", "actual observation status differs")
    return {"provider": PROVIDER, "cases": len(CONTROLS), "qualificationEligible": True, "productionQualification": False, "claimScope": row["claimScope"], "modelCalls": 0}

def artifact_locator(row, raw):
    return {"schema": "legion-python-code-command-sdk-artifact/1", "provider": PROVIDER, "file": "code_python.json", "digest": digest(raw), "bytes": len(raw), "qualificationDigest": row["qualificationDigest"], "qualificationEligible": row["qualificationEligible"], "productionQualification": False}

def child_record(execution_path, stdout_path, stderr_path, record_path):
    execution = parsed(Path(execution_path).read_bytes())
    keys(execution, ("schema", "productionQualification", "status", "stdout", "stderr"))
    require(execution["schema"] == "legion-python-code-command-child-execution/1" and execution["productionQualification"] is False, "child execution identity differs")
    same(execution["status"], {"success": True, "exitCode": 0, "signal": None}, "actual child control harness failed")
    streams = []
    for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        path = Path(path)
        require(path.is_file() and not path.is_symlink(), "original child stream unsafe/missing")
        raw = path.read_bytes()
        same(execution[name], {"file": "child." + name + ".log", "bytes": len(raw), "sha256": digest(raw)}, "child original raw stream differs")
        streams.append(raw)
    marker = b"PYTHON_CODE_COMMAND_SDK_ACCURACY_ARTIFACT "
    locators = [parsed(line.split(marker, 1)[1]) for line in streams[0].splitlines() if marker in line]
    require(len(locators) == 1, "one exact Python child artifact emission required")
    path = Path(record_path)
    require(path.is_file() and not path.is_symlink(), "original Python record missing/unsafe")
    raw = path.read_bytes()
    row = parsed(raw)
    same(locators[0], artifact_locator(row, raw), "authenticated child locator differs from original record bytes")
    text = streams[0].decode()
    require(re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", text) == [("1", "0", "0")] and len(re.findall(r"\btest real_python_code_command_accuracy \.\.\.", text)) == 1, "named actual child control did not execute exactly once")
    return row

def validate_retained(root, row, paths):
    """Offline replay consumes original authenticated bytes, preserving original paths."""
    keys(paths, ("childExecution", "childStdout", "childStderr", "pythonEnrollment", "providerRecord"))
    observed = child_record(paths["childExecution"], paths["childStdout"], paths["childStderr"], paths["providerRecord"])
    same(observed, row, "indexed row differs from original child artifact")
    enrollment = retained_enrollment(root, row, paths["pythonEnrollment"], False)
    return validate_record(root, row, live=False, enrollment=enrollment)

def validate_records(root, receipts, live=True):
    root, receipts = Path(root).resolve(), Path(receipts)
    require(receipts.is_dir() and not receipts.is_symlink(), "original retained output missing/unsafe")
    require({p.name for p in receipts.glob("code_*.json")} == {"code_python.json"}, "Python record inventory differs")
    row = child_record(receipts / "child-execution.json", receipts / "child.stdout.log", receipts / "child.stderr.log", receipts / "code_python.json")
    enrollment = retained_enrollment(root, row, receipts / "python-sdk-enrollment.json", live)
    return {"records": [validate_record(root, row, live=live, enrollment=enrollment)], "modelCalls": 0}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--receipts", type=Path, required=True)
    args = p.parse_args()
    result = validate_records(args.root, args.receipts)
    print("PYTHON_CODE_COMMAND_SDK_ACCURACY_SUMMARY " + json.dumps(result, sort_keys=True, separators=(",", ":")))

if __name__ == "__main__": main()
