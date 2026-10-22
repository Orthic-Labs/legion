#!/usr/bin/env python3
"""Check retained code SDK known-answer evidence against original provider contracts.

This checks source-bound fixture observations, not authenticated CI retrieval.
Registration still requires its separate maintainer-owned GitHub attestation.
"""
import argparse
import hashlib
import json
import runpy
from pathlib import Path, PurePosixPath
import re
import tarfile
from urllib.parse import quote

HARNESS = "engine/crates/legion-audit/tests/real_code_command_accuracy.rs"
FIXTURES = "scripts/ci/fixtures/audit-code-sdk-accuracy"
POLICY = "legion-real-code-command-fixture-v1"
PROVIDERS = tuple("code." + name for name in ("c-family", "dotnet", "go", "javascript", "jvm", "long-tail", "mobile", "php-ruby", "python", "rust"))
CONTROLS = ("positive", "nonempty-clean", "vulnerability-positive", "build-tags", "cgo", "workspace", "external-test", "test-failure", "malformed", "missing-tool", "rejected-admission", "absent-sandbox")
TASKS = ("module", "vet", "format", "test", "vulnerability")
GOVULN_HELPER = "scripts/ci/audit-govulncheck-bootstrap.py"
GOVULN_INPUTS = "scripts/ci/audit-govulncheck-inputs.json"
RECEIPT_FIELDS = ("schemaVersion", "receiptId", "requestId", "providerId", "planId", "policyId", "policy", "taskId", "state", "complete", "executable", "command", "cwd", "environmentNames", "sandbox", "processTree", "timing", "exitCode", "signal", "stdout", "stderr", "parser", "gaps")
SOURCE_ROOTS = ["engine/crates/" + crate + "/src" for crate in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")] + ["src/registry/rules", "src/registry/controls", FIXTURES]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HARNESS, GOVULN_HELPER, GOVULN_INPUTS] + ["engine/crates/" + crate + "/Cargo.toml" for crate in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")]
GO_PINS = {"go1.26.7.darwin-arm64.tar.gz": "sha256:020a1e8224811be75163e920bc77e0926a1390a6aeea19bdcf23f74b9d749f6d", "go1.26.7.darwin-amd64.tar.gz": "sha256:92e8b34bff3c89ab16404c595669ac8cb004cc2f676dcbd1f5b87a6b8def3b47"}


def require(value, message):
    if not value:
        raise AssertionError(message)


def keys(value, fields):
    require(isinstance(value, dict) and set(value) == set(fields), "unexpected object fields")


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def receipt_fields(receipt, owner_projection=False):
    """Validate exact SDK fields, including the source-owned denial projection."""
    owner = "audit-native-owner-admission-v1"
    projected = owner_projection and isinstance(receipt, dict) and isinstance(receipt.get("policy"), dict) and receipt["policy"].get("id") == owner
    keys(receipt, RECEIPT_FIELDS + (("executionPolicy", "executionPolicyIdentity") if projected else ()))
    if projected:
        policy = {"externalProcesses": "owner-admission-required", "admissionStatus": "unavailable", "effectiveMode": "deny-external"}
        identity = {"id": owner, "version": 1, "digest": digest(encoded(policy))}
        same(receipt["executionPolicy"], policy, "original owner-admission policy projection differs")
        same(receipt["executionPolicyIdentity"], identity, "original owner-admission identity projection differs")
        same(receipt["policy"], dict(identity, allowed=False, reason="native-owner-admission-unavailable"), "projected owner admission is not the original denial")
        require(receipt["policyId"] == owner, "projected owner-admission policy ID differs")


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def source_file(root, relative):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and str(path) == relative and ".." not in path.parts and "\\" not in relative, "unsafe source path")
    actual = root
    for part in path.parts:
        actual /= part
        require(not actual.is_symlink(), "source symlink refused")
    require(actual.is_file(), "source file missing: " + relative)
    return actual


def generated_session_provenance(relative):
    return re.fullmatch(
        r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json",
        relative,
    ) is not None


def source_files(root):
    files = set(SOURCE_FILES)
    for relative in SOURCE_ROOTS:
        directory = root / relative
        require(directory.is_dir() and not directory.is_symlink(), "source root missing/unsafe")
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "source closure symlink")
            if path.is_file():
                if generated_session_provenance(path.relative_to(root).as_posix()):
                    continue
                files.add(path.relative_to(root).as_posix())
    return sorted(files)


def absolute(value):
    require(isinstance(value, str), "retained absolute path missing")
    require(not any(c in value for c in "\0\r\n"), "retained absolute path contains controls")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts and not value.startswith("//"), "retained path noncanonical")
    return path


def fixture(root, control):
    name = "nonempty-clean" if control in ("missing-tool", "rejected-admission", "absent-sandbox") else control
    paths = ["go.mod", "answer.go", "answer_test.go"]
    if control == "vulnerability-positive":
        paths.append("go.sum")
    if control == "build-tags":
        paths.append("excluded_test.go")
    if control == "cgo":
        paths.append("cgo.go")
    if control == "workspace":
        paths.append("go.work")
    return {path: source_file(root, FIXTURES + "/go/" + name + "/" + path).read_text() for path in paths}


def artifact(stream, retained, scratch, live):
    if retained is None:
        require(stream is None, "absent raw artifact has a receipt")
        return b""
    keys(retained, ("path", "absolutePath", "digest", "bytes", "immutable", "rawBytes"))
    require(isinstance(retained["rawBytes"], list) and all(type(b) is int and 0 <= b <= 255 for b in retained["rawBytes"]), "raw bytes malformed")
    raw = bytes(retained["rawBytes"])
    path = PurePosixPath(retained["path"])
    require(not path.is_absolute() and str(path) == retained["path"] and all(p not in ("..", ".") for p in path.parts) and len(path.parts) > 0, "artifact relative path unsafe")
    require(retained["immutable"] is True and type(retained["bytes"]) is int and retained["bytes"] == len(raw)
            and retained["digest"] == digest(raw), "retained raw artifact differs")
    same(stream, {key: retained[key] for key in ("path", "digest", "bytes", "immutable")}, "SDK receipt/raw artifact linkage differs")
    full = absolute(retained["absolutePath"])
    require(full == scratch / "artifacts" / path, "original artifact root/path differs")
    if live:
        actual = Path(full)
        require(not actual.is_symlink() and actual.is_file() and actual.read_bytes() == raw, "live SDK raw artifact changed")
    return raw


def environment(policy, scratch, tools):
    values = policy["environment"]
    allowed = {"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"}
    expected = {"PATH": values["PATH"], "HOME": values["HOME"]}
    source = absolute(policy["cwd"])
    require(expected["HOME"] == str(source.parent.parent / "home"), "child HOME isolation differs")
    for name, relative in (("TMPDIR", "tmp"), ("TEMP", "tmp"), ("TMP", "tmp"), ("XDG_CACHE_HOME", "cache/xdg"), ("CARGO_TARGET_DIR", "cache/cargo-target"), ("npm_config_cache", "cache/npm"), ("RUFF_CACHE_DIR", "cache/ruff"), ("MYPY_CACHE_DIR", "cache/mypy"), ("PYTHONPYCACHEPREFIX", "cache/pycache"), ("GOCACHE", "cache/go-build")):
        expected[name] = str(scratch / relative)
        allowed.add(name)
    expected.update({"PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1", "PYTHONDONTWRITEBYTECODE": "1", "NO_COLOR": "1", "CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOENV": "off"})
    allowed.update(expected)
    expected["GOROOT"] = str(tools["go"][0].parent.parent)
    allowed.add("GOROOT")
    expected["GOMODCACHE"] = values["GOMODCACHE"]
    absolute(expected["GOMODCACHE"])
    allowed.add("GOMODCACHE")
    require(expected["PATH"] == str(tools["go"][0].parent) + ":" + str(tools["govulncheck"][0].parent), "toolchain PATH differs")
    same(values, expected, "SDK environment differs/unbound names")
    same(policy["environmentAllowlist"], sorted(allowed), "SDK environment allowlist differs")
    return values, sorted(allowed)


def execution(item, policy, control, plan, scratch, toolchain, enrollment, live):
    keys(item, ("request", "executionReceipt", "stdout", "stderr"))
    req, receipt = item["request"], item["executionReceipt"]
    keys(receipt, RECEIPT_FIELDS)
    keys(req, ("schemaVersion", "requestId", "providerId", "planId", "policyId", "taskId", "executable", "args", "cwd", "origin", "shell", "expectedDigest", "acceptedExitCodes", "versionArgs", "skipVersionProbe", "versionRequirement", "environment", "environmentAllowlist", "sensitiveArgumentIndexes", "sensitiveEnvironmentNames", "requiresNetworkSandbox", "sandbox", "timeoutMs", "stdoutLimit", "stderrLimit"))
    task = req["taskId"]
    require(task in TASKS and re.fullmatch(r"legion-audit/[0-9a-f]{64}", req["requestId"] or ""), "SDK task/request identity differs")
    cwd = absolute(policy["cwd"])
    tools = {name: (absolute(value[0]), value[1]) for name, value in policy["toolIdentities"].items()}
    require(set(tools) == {"go", "gofmt", "govulncheck"}, "host tool identities incomplete")
    same(policy["toolIdentities"], toolchain, "host Go/gofmt identities changed between controls")
    for name, (path, sha) in tools.items():
        require(path.name == name and is_digest(sha), "host tool identity malformed")
        if live:
            require(digest(Path(path).read_bytes()) == sha and not Path(path).read_bytes().startswith(b"#!"), "live tool bytes differ")
    wrapper = policy["wrapper"]
    require(wrapper["path"] == "/usr/bin/sandbox-exec" and is_digest(wrapper["digest"]), "native sandbox wrapper differs")
    if live:
        require(digest(Path(wrapper["path"]).read_bytes()) == wrapper["digest"], "live sandbox wrapper differs")
    text = '(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath "' + str(cwd).replace('\\', '\\\\').replace('"', '\\"') + '"))\n'
    sha = digest(text.encode()).removeprefix("sha256:")
    profile = scratch / "sandbox" / ("audit-" + sha + ".sb")
    sandbox_id = "sandbox:macos:" + sha
    same(policy["profile"], {"path": str(profile), "text": text, "receiptId": sandbox_id}, "native sandbox profile differs")
    env, allowlist = environment(policy, scratch, tools)
    require(env["GOMODCACHE"] == enrollment["moduleCache"]["root"], "SDK module cache differs from enrollment")
    prefix = ["-f", str(profile), "--"]
    if task == "vulnerability":
        stage = scratch / "cache" / "govulncheck" / hashlib.sha256(b"").hexdigest()
        home = stage.parent / ("home-" + hashlib.sha256(b"").hexdigest())
        db_url = "file://" + quote(str(absolute(enrollment["database"]["root"])), safe="/-._~:") + "/"
        # Root-module source.join("") retains its trailing POSIX separator.
        argv = ["-C", str(stage) + "/", "-mode=source", "-scan=symbol", "-test", "-json", "-db", db_url, "./..."]
        version = prefix + [str(tools["govulncheck"][0]), "-db", db_url, "-version"]
        env = dict(env, GOWORK="off", GOFLAGS="-mod=readonly", CGO_ENABLED="0", HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"), APPDATA=str(home / "AppData/Roaming"))
        allowlist = sorted(set(allowlist) | set(env))
        same(policy["vulnerabilityCommand"], {"args": argv, "versionArgs": version, "environment": env, "environmentAllowlist": allowlist}, "vulnerability command contract differs")
    else:
        argv = {"module": ["list", "-m"], "vet": ["vet", "./..."], "format": ["-l", "."], "test": ["test", "-count=1", "./..."]}[task]
        version = prefix + [str(tools["go"][0]), "version"] + ([str(tools["gofmt"][0])] if task == "format" else [])
    executable_name = "gofmt" if task == "format" else "govulncheck" if task == "vulnerability" else "go"
    expected = dict(req, schemaVersion=1, providerId="code.go", planId=plan, policyId="audit", executable=wrapper["path"], args=prefix + [str(tools[executable_name][0])] + argv,
                    cwd=str(cwd), origin="TargetProject", shell=False, expectedDigest=wrapper["digest"], acceptedExitCodes=[0, 1, 2] if task == "vet" else [0],
                    versionArgs=version, skipVersionProbe=False, versionRequirement=None, environment=env, environmentAllowlist=allowlist,
                    sensitiveArgumentIndexes=[], sensitiveEnvironmentNames=[], requiresNetworkSandbox=True,
                    sandbox=None if control == "absent-sandbox" else {"id": sandbox_id, "network": True, "filesystemScope": str(cwd)}, timeoutMs=120000, stdoutLimit=33554432, stderrLimit=33554432)
    same(req, expected, "original SDK argv/environment/bounds/sandbox request differs")
    require(receipt["schemaVersion"] == 1 and receipt["requestId"] == req["requestId"] and receipt["receiptId"] == "receipt:" + req["requestId"]
            and receipt["providerId"] == "code.go" and receipt["planId"] == plan and receipt["taskId"] == task
            and receipt["cwd"] == str(cwd) and receipt["environmentNames"] == sorted(env), "actual SDK receipt identity differs")
    same(receipt["command"], {"executable": req["executable"], "args": req["args"], "environmentNames": sorted(env), "redactedArgumentIndexes": [], "redactedEnvironmentNames": []}, "SDK actual command differs")
    p = receipt["policy"]
    require(p is not None and receipt["policyId"] == p["id"], "actual decision policy ID differs")
    require(p is not None and p["version"] == 1 and is_digest(p["digest"]), "actual admission receipt missing")
    rejected, absent = control == "rejected-admission", control == "absent-sandbox"
    if rejected:
        require(p["allowed"] is False and p["id"] == "audit-native-owner-admission-v1"
                and p["reason"] == "native-owner-admission-unavailable"
                and p["digest"] == digest(encoded({"externalProcesses": "owner-admission-required", "admissionStatus": "unavailable", "effectiveMode": "deny-external"})), "rejection is not actual owner-admission denial")
    else:
        require(p["allowed"] is True and p["id"] == POLICY and p["digest"] == digest(encoded(policy)), "constructed SDK admission binding differs")
    keys(p, ("id", "version", "digest", "allowed", "reason"))
    tree = receipt["processTree"]
    keys(tree, ("started", "terminated", "hardKilled", "reaped", "detail"))
    keys(receipt["timing"], ("startedAtMs", "completedAtMs", "durationMs"))
    require(all(type(v) is int and v >= 0 for v in receipt["timing"].values()), "SDK timing malformed")
    keys(receipt["parser"], ("attempted", "succeeded", "error"))
    require(receipt["parser"] == {"attempted": False, "succeeded": False, "error": None}, "raw SDK receipt parser projection differs")
    same(receipt["sandbox"], {"required": True, "receiptId": None if absent else sandbox_id, "networkEnabled": not absent}, "SDK actual sandbox differs")
    if rejected or absent:
        same(tree, {"started": False, "terminated": False, "hardKilled": False, "reaped": False, "detail": None}, "SDK refusal launched process")
        require(receipt["signal"] is None, "SDK refusal has process signal")
        require(receipt["state"] == ("unauthorized_effect" if rejected else "sandbox_missing") and receipt["complete"] is False
                and tree["started"] is False and receipt["exitCode"] is None and receipt["executable"] is None
                and receipt["gaps"] and receipt["parser"]["attempted"] is False, "SDK refusal executed or became clean")
    else:
        require(tree["started"] is tree["terminated"] is tree["reaped"] is True and tree["hardKilled"] is False and receipt["signal"] is None, "actual child lifecycle incomplete")
        executable = receipt["executable"]
        require(executable["canonicalPath"] == executable["requestedPath"] == wrapper["path"] and executable["digest"] == wrapper["digest"] and executable["digestState"] == "sealed", "executed wrapper identity differs")
        v = executable["version"]
        require(v["skippedByPolicy"] is False and v["args"] == version, "actual version probe argv differs")
        malformed_probe = control == "malformed" and receipt["state"] == "unsealed_executable"
        if malformed_probe:
            require(v["qualified"] is False and type(v["exitCode"]) is int and v["exitCode"] != 0
                    and "invalid go version" in v["output"] and receipt["complete"] is False
                    and receipt["exitCode"] == v["exitCode"] and receipt["gaps"], "malformed control did not prove authentic failed version probe")
        else:
            require(v["qualified"] is True and v["exitCode"] == 0
                    and ("v1.9.0" if task == "vulnerability" else "go1.26.7") in v["output"], "actual version probe incomplete")
            good = receipt["exitCode"] in req["acceptedExitCodes"]
            require(receipt["state"] == ("completed" if good else "failed") and receipt["complete"] is good, "failed process promoted to successful receipt")
    out = artifact(receipt["stdout"], item["stdout"], scratch, live)
    err = artifact(receipt["stderr"], item["stderr"], scratch, live)
    return task, receipt, out.decode("utf-8"), err.decode("utf-8"), req


def required_contract(root, provider):
    """Parse only the source-owned literal LanguageConfig; fail closed on new syntax."""
    name = provider.removeprefix("code.").replace("-", "_")
    source = source_file(root, "engine/crates/legion-audit/src/native_providers/code/" + name + ".rs").read_text()
    match = re.search(r"pub const CONFIG: LanguageConfig\s*=\s*LanguageConfig::new\((.*?)\);", source, re.S)
    require(match is not None, "source language contract syntax changed")
    tokens = re.findall(r'"(?:[^"\\]|\\.)*"|[\[\](),&]|[^\s\[\](),&]+', match[1])
    cursor = 0
    def value():
        nonlocal cursor
        require(cursor < len(tokens), "incomplete language contract")
        token = tokens[cursor]
        cursor += 1
        if token == "&":
            return value()
        if token in ("[", "("):
            end = "]" if token == "[" else ")"
            out = []
            while cursor < len(tokens) and tokens[cursor] != end:
                out.append(value())
                if tokens[cursor] == ",":
                    cursor += 1
                else:
                    require(tokens[cursor] == end, "language contract separator differs")
            require(cursor < len(tokens), "language contract unclosed")
            cursor += 1
            return out
        require(token.startswith('"'), "nonliteral language contract refused")
        return parsed(token)
    values = []
    while cursor < len(tokens):
        values.append(value())
        if cursor < len(tokens):
            require(tokens[cursor] == ",", "language contract argument separator differs")
            cursor += 1
    require(len(values) == 5, "language contract argument count differs")
    return {"tools": values[3], "extensions": values[1], "variants": values[2], "requiredContext": values[4],
            "coverageRequirement": "bounded SDK accuracy requires every declared tool/context & source-owned control; arbitrary-input, platform & variant completeness remains distinct"}


def validate_tree(receipts, toolchain, live, retained_path=None):
    ref = toolchain["tree"]
    keys(ref, ("file", "digest", "bytes", "fileCount"))
    require(ref["file"] == "toolchain-tree.json", "runtime manifest path differs")
    path = Path(retained_path) if retained_path is not None else receipts / ref["file"]
    require(path.is_file() and not path.is_symlink(), "runtime manifest missing/unsafe")
    raw = path.read_bytes()
    require(ref["digest"] == digest(raw) and type(ref["bytes"]) is int and ref["bytes"] == len(raw), "runtime manifest original bytes differ")
    manifest = parsed(raw)
    keys(manifest, ("root", "files"))
    require(manifest["root"] == toolchain["root"] and isinstance(manifest["files"], dict) and manifest["files"]
            and type(ref["fileCount"]) is int and ref["fileCount"] == len(manifest["files"]), "runtime tree identity/count differs")
    for relative, sha in manifest["files"].items():
        path = PurePosixPath(relative)
        require(not path.is_absolute() and str(path) == relative and ".." not in path.parts and is_digest(sha), "runtime tree entry malformed")
    if live:
        archive = Path(toolchain["archive"])
        require(digest(archive.read_bytes()) == GO_PINS.get(archive.name) == toolchain["archiveDigest"], "official runtime archive pin differs")
        files = {}
        with tarfile.open(archive) as package:
            for member in package.getmembers():
                path = PurePosixPath(member.name)
                require(path.parts and path.parts[0] == "go" and not path.is_absolute() and ".." not in path.parts, "runtime archive escapes root")
                require(member.isdir() or member.isfile(), "runtime archive contains unsealed special/link member")
                if member.isfile():
                    relative = path.relative_to("go").as_posix()
                    require(relative not in files, "runtime archive duplicate member")
                    files[relative] = digest(package.extractfile(member).read())
        same(manifest["files"], files, "runtime bytes differ from complete official archive")
        actual = {}
        root = Path(toolchain["root"])
        require(root.is_dir() and not root.is_symlink(), "runtime root unsafe/missing")
        for path in root.rglob("*"):
            require(not path.is_symlink(), "runtime symlink refused")
            if path.is_file():
                actual[path.relative_to(root).as_posix()] = digest(path.read_bytes())
            else:
                require(path.is_dir(), "runtime special file refused")
        same(actual, files, "live compiler/linker/stdlib closure changed")
    for name, sha in toolchain["binaryDigests"].items():
        require(manifest["files"].get("bin/" + name) == sha, "executed binary omitted from runtime tree")
    return manifest


def validate_mutations(case, scratch, live):
    controls = case["requestMutationControls"]
    fields = ("args", "cwd", "executable", "planId")
    require([row["mutatedField"] for row in controls] == list(fields), "same-policy binding mutation controls missing/duplicated")
    source = next(row["request"] for row in case["sdkExecutions"] if row["request"]["taskId"] == "module")
    for row, field in zip(controls, fields):
        keys(row, ("control", "scope", "qualificationEligible", "sourceRequest", "baselineRequest", "mutatedField", "policyDefinition", "policyDecisions", "sdkExecutions", "matched"))
        require(row["control"] == "request-mutation-" + field and row["scope"] == "sdk-exact-policy-boundary"
                and row["qualificationEligible"] is False and row["matched"] is True, "mutation scope/observation differs")
        same(row["sourceRequest"], source, "mutation source is not actual successful SDK request")
        same(row["policyDefinition"], case["policyDefinition"], "mutation used a different authorizer contract")
        baseline = dict(source, requestId="legion-audit/" + digest((source["requestId"] + ":mutation:" + field).encode()).removeprefix("sha256:"))
        same(row["baselineRequest"], baseline, "fresh admitted baseline request differs")
        wanted = dict(baseline)
        wanted[field] = (baseline["args"] + ["--outside-fixture-command"] if field == "args" else
                         str(absolute(baseline["cwd"]).parent) if field == "cwd" else
                         case["policyDefinition"]["toolIdentities"]["go"][0] if field == "executable" else "different-frozen-plan")
        require(len(row["sdkExecutions"]) == 1, "mutation must have exactly one genuine refusal")
        item = row["sdkExecutions"][0]
        keys(item, ("request", "executionReceipt", "stdout", "stderr"))
        same(item["request"], wanted, "mutation did not change exactly one admitted binding")
        same(row["policyDecisions"], [{"requestId": wanted["requestId"], "taskId": wanted["taskId"], "allowed": False, "request": wanted}], "same authorizer did not reject mutated binding")
        r = item["executionReceipt"]
        keys(r, RECEIPT_FIELDS)
        require(r["schemaVersion"] == 1 and r["receiptId"] == "receipt:" + wanted["requestId"] and r["requestId"] == wanted["requestId"]
                and r["providerId"] == wanted["providerId"] and r["planId"] == wanted["planId"] and r["taskId"] == wanted["taskId"] and r["cwd"] == wanted["cwd"]
                and r["policyId"] == POLICY and r["policy"]["id"] == POLICY and r["policy"]["allowed"] is False and r["policy"]["version"] == 1
                and r["policy"]["digest"] == digest(encoded(row["policyDefinition"]))
                and r["state"] == "unauthorized_effect" and r["complete"] is False and r["executable"] is None
                and r["exitCode"] is r["signal"] is None and r["gaps"] and item["stdout"] is item["stderr"] is r["stdout"] is r["stderr"] is None,
                "same-policy denial receipt differs or launched process")
        same(r["environmentNames"], sorted(wanted["environment"]), "mutation actual environment names differ")
        same(r["timing"], {"startedAtMs": 0, "completedAtMs": 0, "durationMs": 0}, "mutation launched timed process")
        same(r["processTree"], {"started": False, "terminated": False, "hardKilled": False, "reaped": False, "detail": None}, "mutation refusal launched process")
        same(r["parser"], {"attempted": False, "succeeded": False, "error": None}, "mutation refusal invoked parser")
        same(r["command"], {"executable": wanted["executable"], "args": wanted["args"], "environmentNames": sorted(wanted["environment"]), "redactedArgumentIndexes": [], "redactedEnvironmentNames": []}, "mutated actual command differs")
        same(r["sandbox"], {"required": True, "receiptId": wanted["sandbox"]["id"], "networkEnabled": True}, "mutation lost original sandbox requirement")
        if live:
            path = Path(scratch) / "mutations" / field / "sdk-execution-0.json"
            require(path.is_file() and not path.is_symlink(), "original mutation refusal missing")
            same(parsed(path.read_bytes()), item, "original mutation SDK evidence changed")



def validate_go_inputs(case, native_receipts, result, scratch, enrollment):
    receipt = next(r for r in native_receipts if r["tool"] == "vulnerability")
    snapshots = receipt["nativeInputSnapshots"]
    keys(snapshots, ("before", "after", "afterError", "unchanged"))
    require(snapshots["unchanged"] is True and snapshots["afterError"] is None, "actual scanner inputs changed/unreadable")
    same(snapshots["before"], snapshots["after"], "scanner input before/after closure differs")
    snap = snapshots["before"]
    keys(snap, ("schema", "databaseRoot", "databaseDigest", "databaseFiles", "sourceRoot", "sourceDigest", "sourceFiles", "moduleCacheRoot", "moduleCacheDigest", "moduleCacheFiles", "verifiedModules", "telemetryHome", "telemetryFiles"))
    require(snap["schema"] == "legion-govulncheck-input-snapshot/1", "native scanner snapshot schema differs")
    for label, enrolled in (("database", enrollment["database"]), ("moduleCache", enrollment["moduleCache"])):
        same({k: snap[label + k[0].upper() + k[1:]] for k in ("root", "files", "digest")}, enrolled, "scanner " + label + " differs from exact enrolled closure")
    stage = scratch / "cache" / "govulncheck" / hashlib.sha256(b"").hexdigest()
    home = stage.parent / ("home-" + hashlib.sha256(b"").hexdigest())
    requests = [row["request"] for row in case["sdkExecutions"] if row["request"]["taskId"] == "vulnerability"]
    require(len(requests) == 1 and requests[0]["environment"]["HOME"] == str(home)
            and absolute(snap["telemetryHome"]) == home, "scanner telemetry home differs from staged SDK HOME")
    # Fresh macOS scanner home contains only the source-created exact off mode.
    # Full snapshot equality above also rejects every execution-time home mutation.
    same(snap["telemetryFiles"], {"Library/Application Support/go/telemetry/mode": digest(b"off")},
         "scanner telemetry closure differs from exact off-mode bytes")
    same(snap["sourceFiles"], case["fixtureSources"], "scanner frozen source closure differs")
    require(snap["sourceRoot"] == str(stage) and snap["sourceDigest"] == digest(encoded(snap["sourceFiles"])), "scanner frozen stage binding differs")
    expected_modules = {}
    for line in case["fixtureFiles"].get("go.sum", "").splitlines():
        name, version, sha = line.split()
        if not version.endswith("/go.mod"):
            expected_modules[name + "@" + version] = sha
    same(snap["verifiedModules"], expected_modules, "official Go module checksum proofs differ")
    r, out, _ = result["vulnerability"]
    if case["control"] == "malformed":
        require(r["state"] in ("failed", "unsealed_executable") and r["complete"] is False and type(r["exitCode"]) is int and r["exitCode"] != 0, "malformed scanner input became clean")
        return
    require(r["state"] == "completed" and r["complete"] is True and r["exitCode"] == 0, "actual scanner failed")
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate scanner JSON field")
        return dict(items)
    decoder = json.JSONDecoder(object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON scanner number"))
    messages, rest = [], out.strip()
    while rest:
        message, end = decoder.raw_decode(rest)
        require(isinstance(message, dict) and len(message) == 1, "scanner JSON message malformed")
        messages.append(message)
        require(len(messages) <= 20000, "scanner JSON stream unbounded")
        rest = rest[end:].lstrip()
    require(messages and set(messages[0]) == {"config"}, "scanner stream lacks initial Config")
    config = messages[0]["config"]
    for key, value in {"protocol_version": "v1.0.0", "scanner_name": "govulncheck", "scanner_version": "v1.9.0", "scan_level": "symbol", "scan_mode": "source", "db_last_modified": "2026-10-21T00:27:29Z", "db": "file://" + quote(enrollment["database"]["root"], safe="/-._~:") + "/"}.items():
        require(config.get(key) == value, "actual scanner Config differs: " + key)
    require(sum("config" in message for message in messages) == 1 and sum("SBOM" in message for message in messages) == 1
            and all(next(iter(message)) in ("config", "SBOM", "progress", "osv", "finding") for message in messages), "scanner Config/SBOM/protocol envelope incomplete")
    if case["control"] == "vulnerability-positive":
        require(any(message.get("osv", {}).get("id") == "GO-2021-0113" for message in messages)
                and any(message.get("finding", {}).get("osv") == "GO-2021-0113" and message["finding"].get("trace") for message in messages), "official known vulnerability absent from original scanner output")


def retained_enrollment(root, row, path, live):
    keys(row["goVulnerability"], ("enrollment",))
    ref = row["goVulnerability"]["enrollment"]
    keys(ref, ("file", "digest", "bytes"))
    require(ref["file"] == "govulncheck-enrollment.json", "enrollment retained filename differs")
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "original enrollment missing/unsafe")
    raw = path.read_bytes()
    require(type(ref["bytes"]) is int and ref["bytes"] == len(raw) and ref["digest"] == digest(raw), "original enrollment bytes/hash differ")
    enrollment = parsed(raw)
    keys(enrollment, ("schema", "qualificationEligible", "inputsDigest", "enrollmentPath", "moduleProxy", "databaseArchivePath", "databaseArchiveDigest", "database", "moduleCache", "go", "scanner", "bootstrapProcesses", "environment"))
    for value in enrollment["environment"].values():
        absolute(value)
    proof = runpy.run_path(str(source_file(root, GOVULN_HELPER)))["verify_enrollment"](root, enrollment, live=live)
    require(all(is_digest(value) for value in proof.values()), "source-owned bootstrap verification incomplete")
    return enrollment


def validate_case(root, case, toolchain, enrollment, live):
    control = case["control"]
    fields = {"caseId", "control", "provider", "scope", "qualificationEligible", "fixtureFiles", "fixtureSources", "inventory", "planDigest", "frozenProvider", "nativeResult", "policyDefinition", "policyDecisions", "sdkExecutions", "expected", "matched"}
    if control == "nonempty-clean":
        fields.add("requestMutationControls")
    keys(case, fields)
    require(control in CONTROLS and case["caseId"] == "code-go-" + control and case["provider"] == "code.go"
            and case["scope"] == ("sdk-boundary-control" if control == "absent-sandbox" else "native-provider-known-answer-fixture")
            and case["qualificationEligible"] is False and case["matched"] is True, "fixed case identity/scope differs")
    files = fixture(root, control)
    hashes = {path: digest(text.encode()) for path, text in files.items()}
    same(case["fixtureFiles"], files, "fixture source bytes differ")
    same(case["fixtureSources"], hashes, "fixture source coverage differs")
    same(case["expected"], {"providerQualificationEligible": False, "rawRule": "gofmt" if control == "positive" else None}, "case expected semantics differ")
    inv = case["inventory"]
    entries = inv["entries"]
    require([entry["path"] for entry in entries] == sorted(files), "frozen inventory omitted/added fixture siblings")
    same(entries, [{"path": path, "symbols": [], "dependencies": ["golang.org/x/text"] if control == "vulnerability-positive" and path == "go.mod" else [], "packageScripts": [],
                    "sourceFile": path.endswith(".go"), "digest": hashes[path]} for path in sorted(files)],
         "frozen inventory metadata/bytes differ")
    require(inv["schemaVersion"] == 1 and inv["repositoryId"] == case["caseId"] and inv["generation"] == "filesystem:" + digest(encoded(entries))
            and inv["digest"] == digest(encoded([1, case["caseId"], inv["generation"], entries])), "original inventory identity differs")
    spec = next(row for row in parsed(source_file(root, "src/registry/providers.json").read_bytes())["providers"] if row["id"] == "code.go")
    frozen = case["frozenProvider"]
    require(is_digest(case["planDigest"]) and frozen["id"] == "code.go" and frozen["version"] == spec["providerVersion"]
            and frozen["configuration"]["denominatorCount"] == len(entries)
            and (frozen["configuration"]["denominatorDigest"] == inv["digest"] if spec["selector"] == {"op": "always"} else frozen["configuration"]["denominatorDigest"] == digest(encoded([inv["digest"], spec["selector"], entries]))), "original frozen provider denominator differs")
    policy = case["policyDefinition"]
    keys(policy, ("id", "version", "scope", "provider", "planDigest", "cwd", "toolIdentities", "wrapper", "profile", "commands", "vulnerabilityCommand", "environment", "environmentAllowlist", "absentSandboxControl", "timeoutMs", "stdoutLimit", "stderrLimit"))
    cwd = absolute(policy["cwd"])
    require(cwd.name == "source" and cwd.parent.name == case["caseId"] and policy["id"] == POLICY and policy["version"] == 1
            and policy["provider"] == "code.go" and policy["planDigest"] == case["planDigest"]
            and policy["scope"] == "exact constructed Go SDK fixtures; no production owner admission"
            and policy["commands"] == ["go list -m", "go vet ./...", "gofmt -l .", "go test -count=1 ./...", "govulncheck -C <frozen-stage> -mode=source -scan=symbol -test -json -db <sealed-official-db> ./..."]
            and policy["absentSandboxControl"] is (control == "absent-sandbox")
            and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 33554432, "exact fixture policy differs")
    # Scratch ownership is recoverable from the bound sandbox path, including refusal cases.
    scratch = absolute(policy["profile"]["path"]).parent.parent
    require(scratch.name == case["caseId"] and scratch.parent.name == "cases", "original SDK scratch case root differs")
    rows = case["sdkExecutions"]
    require(isinstance(rows, list), "actual SDK execution list missing")
    expected_tasks = [] if control == "missing-tool" else ["module"] if control == "absent-sandbox" else list(TASKS[:-1]) if control == "workspace" else list(TASKS)
    require(sorted(row["request"]["taskId"] for row in rows) == sorted(expected_tasks), "required actual SDK tasks missing/duplicated")
    requests = [row["request"]["requestId"] for row in rows]
    require(len(requests) == len(set(requests)), "SDK requests duplicated")
    if live:
        for index, row in enumerate(rows):
            saved = Path(scratch) / ("sdk-execution-" + str(index) + ".json")
            require(saved.is_file() and not saved.is_symlink(), "original pre-assert SDK evidence absent")
            same(parsed(saved.read_bytes()), row, "original SDK record changed after retention")
    result = {task: (receipt, out, err) for task, receipt, out, err, _ in (execution(row, policy, control, case["planDigest"], scratch, toolchain, enrollment, live) for row in rows)}
    expected_decisions = [] if control in ("rejected-admission", "missing-tool") else [{"requestId": row["request"]["requestId"], "taskId": row["request"]["taskId"], "allowed": True, "request": row["request"]} for row in rows]
    same(case["policyDecisions"], expected_decisions, "actual constructed authorizer decisions differ")
    native = case["nativeResult"]
    if control == "absent-sandbox":
        require(native is None, "SDK refusal invented provider execution")
    else:
        complete = control in ("positive", "nonempty-clean", "vulnerability-positive", "external-test")
        require(native["provider"] == "code.go" and native["applicable"] is True and native["complete"] is complete
                and (native["coverage_gaps"] == [] if complete else bool(native["coverage_gaps"]))
                and native["coverage"]["expected"] == len(entries)
                and native["coverage"]["denominator_digest"] == frozen["configuration"]["denominatorDigest"], "original provider coverage/operational gaps differ")
        if complete or control in ("build-tags", "cgo"):
            require(native["coverage"]["examined"] == len(entries), "source/context examination narrowed frozen denominator")
        require(type(native["coverage"]["examined"]) is int and 0 <= native["coverage"]["examined"] <= len(entries), "coverage examined outside frozen denominator")
        native_receipts = native["details"]["nativeProducer"]["toolReceipts"]
        require(len(native_receipts) == len(rows) and len({r["tool"] for r in native_receipts}) == len(rows), "native tool receipts omitted/duplicated")
        for native_receipt in native_receipts:
            actual = next((r for r in rows if r["request"]["taskId"] == native_receipt["tool"]), None)
            require(actual is not None, "native receipt has no genuine SDK execution")
            same(native_receipt["sdkReceipt"], actual["executionReceipt"], "native evidence detached from genuine SDK receipt")
        if control not in ("missing-tool", "rejected-admission", "workspace"):
            validate_go_inputs(case, native_receipts, result, scratch, enrollment)
        if control == "missing-tool":
            require("tool-missing" in encoded(native).decode(), "missing host tools lost gap")
        elif control in ("nonempty-clean", "external-test"):
            require(native["findings"] == [] and result["format"][1] == ""
                    and all(r[0]["state"] == "completed" and r[0]["exitCode"] == 0 for r in result.values()), "nonempty absence control failed")
        elif control == "positive":
            require(result["format"][1].strip() == "answer.go" and result["test"][0]["exitCode"] == 0
                    and any(item["ruleId"] == "gofmt" and item["path"] == "answer.go" and item["line"] == 1 for item in native["details"]["findingEvidence"].values()), "positive actual gofmt finding not demonstrated")
        elif control == "vulnerability-positive":
            require(result["test"][0]["exitCode"] == 0
                    and any(item["ruleId"] == "govulncheck:GO-2021-0113" and item["path"] in ("answer.go", "answer_test.go") and item["line"] == 6 for item in native["details"]["findingEvidence"].values()), "official vulnerable module did not produce actual source finding")
        elif control in ("build-tags", "cgo"):
            require(result["test"][0]["state"] == "completed" and result["test"][0]["exitCode"] == 0
                    and "excluded build-tag test must not run" not in result["test"][1]
                    and "unproven-build-variant" in encoded(native["coverage_gaps"]).decode(), "selected/excluded build-tag control lost its required variant gap")
        elif control == "workspace":
            require(native["coverage"]["examined"] == len(entries) - 1
                    and all(r[0]["state"] == "completed" and r[0]["exitCode"] == 0 for r in result.values())
                    and "workspace-or-replacement-path-closure-unavailable" in encoded(native["coverage_gaps"]).decode(), "unsupported workspace closure narrowed denominator or lost actual gap")
        elif control == "test-failure":
            r, out, _ = result["test"]
            require(r["state"] == "failed" and r["exitCode"] != 0 and "planted test failure" in out, "failed test became clean")
        elif control == "malformed":
            require(any(r[0]["state"] in ("failed", "unsealed_executable") for r in result.values())
                    and any("invalid go version" in r[2] or "invalid go version" in (r[0]["executable"]["version"]["output"] or "") for r in result.values()), "malformed manifest failure missing")
    if control != "absent-sandbox":
        expected_gaps = set()
        tool_gap = lambda task: "code.go:tool-evidence-gap:" + task
        if control == "build-tags":
            expected_gaps = {"code.go:govulncheck:unproven-build-variant:" + path for path in ("answer.go", "excluded_test.go")}
        elif control == "cgo":
            expected_gaps = {"code.go:govulncheck:unproven-build-variant:cgo.go"}
        elif control == "workspace":
            expected_gaps = {tool_gap("vulnerability"), "code.go:govulncheck:workspace-or-replacement-path-closure-unavailable",
                             "code.go:tool-not-run:vulnerability:govulncheck-input-incomplete", "code.go:selection-narrower-than-denominator:3of4"}
        elif control == "missing-tool":
            expected_gaps = {value for task in TASKS for value in (tool_gap(task), "code.go:tool-missing:" + task)}
        elif control == "rejected-admission":
            expected_gaps = {tool_gap(task) for task in TASKS} | {"code.go:native-owner-admission-unavailable"}
        elif control in ("test-failure", "malformed"):
            for task, (receipt, _, _) in result.items():
                if receipt["state"] == "failed":
                    require(type(receipt["exitCode"]) is int and receipt["exitCode"] != 0, "failed SDK main lacks genuine nonzero exit")
                    expected_gaps.update((tool_gap(task), "code.go:tool-failed:" + task + ":exit-" + str(receipt["exitCode"])))
                elif control == "malformed" and receipt["state"] == "unsealed_executable":
                    expected_gaps.update((tool_gap(task), "code.go:tool-failed:" + task + ":unsealed_executable"))
                else:
                    require(receipt["state"] == "completed" and receipt["exitCode"] == 0, "negative control contains unexplained SDK failure")
        require(isinstance(native["coverage_gaps"], list) and all(isinstance(gap, str) for gap in native["coverage_gaps"])
                and len(native["coverage_gaps"]) == len(set(native["coverage_gaps"]))
                and set(native["coverage_gaps"]) == expected_gaps, "native coverage gap set differs from exact actual control outcomes")
    if control == "nonempty-clean":
        validate_mutations(case, scratch, live)
    return {case["caseId"] + "/" + path: sha for path, sha in hashes.items()}


def validate_record(repository_root, row, live=False, enrollment=None):
    root = Path(repository_root).resolve()
    keys(row, ("schema", "kind", "provider", "providerVersion", "productionQualification", "qualificationEligible", "claimScope", "executionPath", "modelCalls", "admissionScope", "binding", "requiredContract", "toolchain", "goVulnerability", "executedScope", "missingControls", "runtimeLimitations", "cases", "metrics", "status", "qualificationDigest"))
    provider = row["provider"]
    require(provider in PROVIDERS and row["schema"] == "legion-code-command-sdk-accuracy/1" and row["kind"] == "code-command-sdk-constructed"
            and row["productionQualification"] is False and type(row["qualificationEligible"]) is bool and row["claimScope"] == "known-answer-fixture-cases"
            and row["executionPath"] == "native-sdk-frozen-plan-self-sourced-code" and type(row["modelCalls"]) is int and row["modelCalls"] == 0
            and row["admissionScope"] == "explicit constructed SDK authorizer; genuine OwnerAdmissionRequired denial control; no production owner-admission claim", "diagnostic identity/eligibility/scope differs")
    require(row["qualificationDigest"] == digest(encoded({k: v for k, v in row.items() if k != "qualificationDigest"})), "original diagnostic digest differs")
    required = required_contract(root, provider)
    same(row["requiredContract"], required, "original whole-provider contract narrowed")
    spec = next(item for item in parsed(source_file(root, "src/registry/providers.json").read_bytes())["providers"] if item["id"] == provider)
    spec = {k: v for k, v in spec.items() if k != "benchmark"}
    bound = row["binding"]
    keys(bound, ("providerSpec", "providerSpecDigest", "sources", "sourcesDigest", "fixtureSources", "fixtureSourcesDigest", "fixture"))
    sources = {relative: digest(source_file(root, relative).read_bytes()) for relative in source_files(root)}
    require(row["providerVersion"] == spec["providerVersion"] and bound["fixture"] == HARNESS
            and bound["providerSpecDigest"] == digest(encoded(spec)) and bound["sourcesDigest"] == digest(encoded(sources)), "provider/source binding differs")
    same(bound["providerSpec"], spec, "source provider spec differs")
    same(bound["sources"], sources, "full SDK/production/fixture source closure stale")
    toolchain = row["toolchain"]
    keys(toolchain, ("version", "root", "archive", "archiveDigest", "binaryDigests", "tree"))
    go_root, archive = absolute(toolchain["root"]), absolute(toolchain["archive"])
    require(toolchain["version"] == "go1.26.7" and GO_PINS.get(archive.name) == toolchain["archiveDigest"]
            and set(toolchain["binaryDigests"]) == {"go", "gofmt"} and all(is_digest(v) for v in toolchain["binaryDigests"].values()), "official pinned Go archive/binary identities differ")
    if live:
        require(digest(Path(archive).read_bytes()) == toolchain["archiveDigest"] and Path(go_root, "VERSION").read_text().splitlines()[0] == "go1.26.7", "live official Go toolchain differs")
        with tarfile.open(archive) as package:
            for name, sha in toolchain["binaryDigests"].items():
                member = package.getmember("go/bin/" + name)
                require(member.isfile() and digest(package.extractfile(member).read()) == sha, "executed Go binary differs from official archive")
    require(enrollment is not None, "retained official vulnerability enrollment required")
    same(enrollment["go"]["archiveDigest"], toolchain["archiveDigest"], "scanner compiler archive differs from actual toolchain")
    require(enrollment["go"]["runtime"]["root"] == str(go_root), "scanner compiler runtime differs")
    identities = {name: [str(go_root / "bin" / name), sha] for name, sha in toolchain["binaryDigests"].items()}
    identities["govulncheck"] = [enrollment["scanner"]["path"], enrollment["scanner"]["digest"]]
    fixtures = {}
    if provider == "code.go":
        same(required["tools"], ["module", "format", "vet", "test", "vulnerability"], "Go original required tool contract changed")
        same(required["requiredContext"], ["modules", "buildTags"], "Go original context contract changed")
        same(required["variants"], [["go", ["go"]]], "Go original language variants changed")
        same(required["extensions"], ["go"], "Go original source extension contract changed")
        require([c["control"] for c in row["cases"]] == list(CONTROLS) and row["executedScope"] == ["module", "format", "vet", "test", "vulnerability"]
                and row["status"] == "observed-known-answer-controls", "fixed full SDK control corpus incomplete")
        for case in row["cases"]:
            fixtures.update(validate_case(root, case, identities, enrollment, live))
        missing = []
        limitations = [{"control": "build-tags", "scope": "excluded-build-variants", "providerComplete": False},
                       {"control": "cgo", "scope": "excluded-cgo-source", "providerComplete": False},
                       {"control": "workspace", "scope": "workspace-path-closure-unavailable", "providerComplete": False}]
    else:
        require(row["cases"] == row["executedScope"] == [] and row["status"] == "unavailable", "unexecuted language/platform gained coverage")
        missing = [{"scope": "entire-provider-contract", "reason": "not exercised by this Go fixture slice", "required": required}]
        limitations = []
        # Harness retains shared corpus binding in all records, never as execution credit.
        for control in CONTROLS:
            fixtures.update({"code-go-" + control + "/" + p: digest(t.encode()) for p, t in fixture(root, control).items()})
    eligible = provider == "code.go"
    require(row["qualificationEligible"] is eligible, "bounded SDK eligibility not derived from complete original control matrix")
    same(row["missingControls"], missing, "missing original qualification dependencies dropped")
    same(row["runtimeLimitations"], limitations, "actual runtime variant/workspace gaps dropped")
    same(bound["fixtureSources"], fixtures, "entire fixture corpus binding differs")
    require(bound["fixtureSourcesDigest"] == digest(encoded(fixtures)), "fixture corpus digest differs")
    count = len(CONTROLS) if provider == "code.go" else 0
    same(row["metrics"], {"cases": count, "matched": count, "mismatched": 0, "wholeProviderQualified": False, "boundedSdkAccuracyQualified": eligible}, "bounded SDK metrics or arbitrary-input qualification differs")
    return {"provider": provider, "cases": count, "qualificationEligible": eligible, "productionQualification": False, "claimScope": row["claimScope"], "missingControls": missing}


def artifact_locator(row, raw):
    return {"schema": "legion-code-command-sdk-artifact/1", "provider": row["provider"],
            "file": row["provider"].replace(".", "_") + ".json", "digest": digest(raw), "bytes": len(raw),
            "qualificationDigest": row["qualificationDigest"], "qualificationEligible": row["qualificationEligible"], "productionQualification": False}


def child_records(execution_path, stdout_path, stderr_path, record_paths):
    execution = parsed(Path(execution_path).read_bytes())
    keys(execution, ("schema", "productionQualification", "status", "stdout", "stderr"))
    require(execution["schema"] == "legion-code-command-child-execution/1" and execution["productionQualification"] is False,
            "child execution provenance differs")
    same(execution["status"], {"success": True, "exitCode": 0, "signal": None}, "actual child harness failed")
    retained = []
    for stream, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        ref = execution[stream]
        keys(ref, ("file", "bytes", "sha256"))
        require(ref["file"] == "child." + stream + ".log", "child raw stream path differs")
        path = Path(path)
        require(not path.is_symlink() and path.is_file(), "child raw stream unsafe/missing")
        raw = path.read_bytes()
        require(type(ref["bytes"]) is int and len(raw) == ref["bytes"] and digest(raw) == ref["sha256"], "child original raw stream differs")
        retained.append(raw)
    locators = [parsed(line.split(b"CODE_COMMAND_SDK_ACCURACY_ARTIFACT ", 1)[1]) for line in retained[0].splitlines() if b"CODE_COMMAND_SDK_ACCURACY_ARTIFACT " in line]
    require([value["provider"] for value in locators] == list(PROVIDERS), "all ten actual child artifact emissions required exactly once")
    keys(record_paths, PROVIDERS)
    rows = []
    for locator in locators:
        path = Path(record_paths[locator["provider"]])
        require(path.is_file() and not path.is_symlink(), "original provider artifact missing/unsafe")
        raw = path.read_bytes()
        row = parsed(raw)
        same(locator, artifact_locator(row, raw), "child artifact locator differs from original provider bytes")
        rows.append(row)
    text = retained[0].decode("utf-8")
    require(re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", text) == [("1", "0", "0")]
            and len(re.findall(r"\btest real_code_command_accuracy \.\.\.", text)) == 1, "child fixture did not execute exactly once")
    return rows


def validate_retained(root, row, paths):
    """Exact archived family metadata, replayed without original host paths."""
    keys(paths, ("toolchainTree", "childExecution", "childStdout", "childStderr", "govulnEnrollment", "providerRecords"))
    rows = child_records(paths["childExecution"], paths["childStdout"], paths["childStderr"], paths["providerRecords"])
    require(sum(encoded(value) == encoded(row) for value in rows) == 1, "indexed record differs from original child emission")
    require(all(value["toolchain"] == rows[0]["toolchain"] and value["goVulnerability"] == rows[0]["goVulnerability"] for value in rows), "shared proof metadata differs between original emissions")
    manifest = validate_tree(None, rows[0]["toolchain"], False, paths["toolchainTree"])
    enrollment = retained_enrollment(root, rows[0], paths["govulnEnrollment"], False)
    same(manifest, {key: enrollment["go"]["runtime"][key] for key in ("root", "files")}, "executed compiler runtime differs from scanner bootstrap closure")
    for value in rows:
        validate_record(root, value, enrollment=enrollment)
    return validate_record(root, row, enrollment=enrollment)


def validate_records(root, receipts, live=True):
    receipts = Path(receipts)
    require(receipts.is_dir() and not receipts.is_symlink(), "retained output directory missing/unsafe")
    expected = {p.replace(".", "_") + ".json" for p in PROVIDERS}
    require({p.name for p in receipts.glob("code_*.json")} == expected, "all ten explicit provider records required")
    rows = child_records(receipts / "child-execution.json", receipts / "child.stdout.log", receipts / "child.stderr.log", {provider: receipts / (provider.replace(".", "_") + ".json") for provider in PROVIDERS})
    for row in rows:
        path = receipts / (row["provider"].replace(".", "_") + ".json")
        require(path.is_file() and not path.is_symlink(), "provider record missing/unsafe")
        same(parsed(path.read_bytes()), row, "child raw emission differs from retained record")
    require(all(row["toolchain"] == rows[0]["toolchain"] and row["goVulnerability"] == rows[0]["goVulnerability"] for row in rows), "shared proof metadata differs between records")
    manifest = validate_tree(receipts, rows[0]["toolchain"], live)
    enrollment = retained_enrollment(root, rows[0], receipts / "govulncheck-enrollment.json", live)
    same(manifest, {key: enrollment["go"]["runtime"][key] for key in ("root", "files")}, "executed compiler runtime differs from scanner bootstrap closure")
    summaries = [validate_record(root, row, live=live, enrollment=enrollment) for row in rows]
    return {"records": summaries, "modelCalls": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    result = validate_records(args.root.resolve(), args.receipts, live=True)
    print("CODE_COMMAND_SDK_ACCURACY_SUMMARY " + json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
