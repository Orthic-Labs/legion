#!/usr/bin/env python3
"""Fixed Semgrep Python known-answer controls; no production admission claim."""
import argparse
import hashlib
import hmac
import json
import math
from pathlib import Path, PurePosixPath
import re
import runpy

ID = "legacy.security.sast"
FAMILY_SCOPE = "constructed Python controls for two packaged intrafile taint rules; no auto parity, population accuracy, production admission or vulnerability adjudication"
HARNESS = "engine/crates/legion-audit/tests/semgrep_accuracy.rs"
GATE = "scripts/ci/audit-semgrep-provider-accuracy.py"
RULE = "src/registry/rules/opengrep/legion-core.yml"
PROVISIONER = "scripts/ci/provision-python-qualification-tools.py"
LOCKS = ["scripts/ci/python-tool-locks/semgrep-macos-arm64-cp314.json", "scripts/ci/python-tool-locks/semgrep-macos-arm64-cp314.txt"]
TREES = ["engine/crates/legion-audit/src", "engine/crates/legion-effects/src", "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src", "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls"]
FILES = ["engine/Cargo.toml", "engine/Cargo.lock", *[f"engine/crates/{c}/Cargo.toml" for c in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")], HARNESS, GATE, PROVISIONER, *LOCKS]
WHEELS = {"sha256:ca54b5cc71c832b56c9cf07fa17f087917b203dacb652d74be71aa8006f5a710": "sha256:5b8937bf9596ad8b61fa8aeb4729ec5f0119d5e76f566b76cd6d0562b0d61032", "sha256:4e9f494134b676c73722e1f5b7c2750c94491dddc0e8f337cb9560b0b78d20ce": "sha256:02faa1d3caa053d4bb64c71d68772006ab92488abd3d4f992e45a164cfe1ae21"}
FLAGS = ["scan", "--config", "@legion-packaged-core", "--json", "--metrics", "off", "--disable-version-check", "--disable-nosem", "--no-rewrite-rule-ids", "--strict", "--verbose", "--no-error", "--no-git-ignore"]
FIXTURES = {
    "shell-planted": ('import os\nfrom flask import request\nos.system(request.args.get("cmd")) # nosemgrep\n', "legion-command-injection-shell"),
    "shell-clean": ('import os\nfrom flask import request\nsupplied = request.args.get("cmd")\nos.system("printf fixed") # nosemgrep\n', None),
    "sql-planted": ('from flask import request\ndef query(cursor):\n    cursor.execute(request.args.get("sql")) # nosemgrep\n', "legion-sql-interpolation"),
    "sql-clean": ('from flask import request\ndef query(cursor):\n    supplied = request.args.get("sql")\n    cursor.execute("SELECT 1") # nosemgrep\n', None),
    "operational-error": ("def foo(a)\n    tree = ElementTree.parse('country_data.xml')\n    root = tree.getroot()\n", None),
    "missing-tool": ("print('fixed')\n", None),
}

def require(ok, message):
    if not ok:
        raise AssertionError(message)

def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()

def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class _JsonNumber:
    """Preserve original numeric token while hashing Rust-issued JSON bytes."""
    def __init__(self, token, floating=False):
        self.token = token
        self.floating = floating
        if floating:
            require(math.isfinite(float(token)), "non-finite JSON number")


def _raw_pairs(items):
    require(len(items) == len(dict(items)), "duplicate JSON key")
    return dict(items)


def _raw_json_value(raw):
    return json.loads(raw, object_pairs_hook=_raw_pairs,
                      parse_int=lambda token: _JsonNumber(token),
                      parse_float=lambda token: _JsonNumber(token, floating=True),
                      parse_constant=lambda _: require(False, "non-JSON number"))


def _canonical_raw_value(value):
    if isinstance(value, _JsonNumber):
        return value.token
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" +
                               _canonical_raw_value(value[key]) for key in sorted(value)) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_canonical_raw_value(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def record_digest(raw_record):
    """Hash canonical key order while retaining Rust-issued numeric spellings."""
    parsed = _raw_json_value(raw_record)
    require(isinstance(parsed, dict) and "qualificationDigest" in parsed,
            "Semgrep record digest field absent")
    claimed = parsed.pop("qualificationDigest")
    require(isinstance(claimed, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", claimed),
            "Semgrep record digest shape differs")
    actual = digest(_canonical_raw_value(parsed).encode())
    require(claimed == actual, "record digest differs")
    return actual

def load(path):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON key")
        return dict(items)
    return json.loads(path.read_bytes(), object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON value"))

def absolute(value):
    require(isinstance(value, str), "absolute path absent")
    p = PurePosixPath(value)
    require(p.is_absolute() and str(p) == value and ".." not in p.parts and not value.startswith("//"), "noncanonical absolute path")
    return p

def generated_session_provenance(relative):
    # Generated host evidence only; all other source-root files remain bound.
    return re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", relative) is not None


def sources(root):
    out = {}
    for relative in TREES + FILES:
        path = root / relative
        require(path.exists() and not path.is_symlink(), "source closure absent/symlink")
        for item in path.rglob("*") if path.is_dir() else [path]:
            require(not item.is_symlink(), "source closure contains symlink")
            if item.is_file() and not generated_session_provenance(item.relative_to(root).as_posix()):
                out[item.relative_to(root).as_posix()] = digest(item.read_bytes())
    return dict(sorted(out.items()))

def contract(root):
    return {"version": "1.141.0", "rulesSource": RULE, "rulesDigest": digest((root / RULE).read_bytes()), "ruleIds": ["legion-command-injection-shell", "legion-sql-interpolation"], "languages": ["python", "javascript", "typescript"], "scope": "two packaged intrafile taint rules only; no auto-rules parity or vulnerability adjudication", "suppression": "disabled", "exitCodes": [0]}

def enrollment(value, root, *, live):
    require(value["schema"] == "legion-python-tool-enrollment/1", "Python enrollment schema differs")
    tool = value["tool"]
    require(tool["name"] == "semgrep" and tool["version"] == "1.141.0" and tool["wheelSha256"] in WHEELS, "official Semgrep pin differs")
    runtime = value["runtime"]
    require(runtime["root"] == "/" and runtime["roots"], "runtime roots absent")
    roots = [absolute(p) for p in runtime["roots"]]
    require(len(roots) == len(set(roots)), "duplicate runtime roots")
    stdlib = absolute(value["interpreter"]["stdlibRoot"])
    require(runtime["exclusions"] in ([], [str(stdlib / "site-packages")]), "runtime excludes unrelated code")
    require(runtime["digest"] == digest(encoded({key: runtime[key] for key in ("absent", "files", "links", "roots")})), "runtime manifest digest differs")
    require(re.fullmatch(r"3\.14\.7", value["interpreter"]["version"]), "managed interpreter version differs")
    for name, expected in runtime["files"].items():
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and str(relative) == name and ".." not in relative.parts and any((PurePosixPath("/") / relative).is_relative_to(r) for r in roots), "runtime file escapes roots")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", expected), "runtime digest shape differs")
        if live:
            require(digest(Path("/", name).read_bytes()) == expected, "live runtime member differs")
    cores = [(name, d) for name, d in runtime["files"].items() if name.endswith("/semgrep/bin/semgrep-core")]
    require(len(cores) == 1 and cores[0][1] == WHEELS[tool["wheelSha256"]], "native core pin differs")
    for key in ("launcher", "interpreter"):
        path = absolute(value[key]["path"])
        require(runtime["files"].get(str(path).removeprefix("/")) == value[key]["digest"], "actual launcher/interpreter absent from closure")
    require(value["lock"]["digest"] == digest((root / LOCKS[0]).read_bytes()), "dependency lock differs")
    lock = load(root / LOCKS[0])
    locked_tool = next(w for w in lock["wheels"] if w["name"] == "semgrep")
    require(lock["schema"] == "legion-python-tool-lock/1" and lock["tool"] == {"name": "semgrep", "version": "1.141.0"} and lock["target"] == {"implementation": "cpython", "machine": "arm64", "minimumMacOS": "15.0", "platform": "darwin", "python": "3.14"}, "source lock target differs")
    require("sha256:" + locked_tool["sha256"] == tool["wheelSha256"] and locked_tool["version"] == tool["version"], "observed wheel not selected by source lock")
    require(absolute(value["lock"]["path"]).name == PurePosixPath(LOCKS[0]).name, "dependency lock path differs")
    absent = runtime["absent"]
    require(isinstance(absent, list) and absent == sorted(set(absent)), "absent loader candidates differ")
    for name in absent:
        require(isinstance(name, str) and PurePosixPath(name).is_absolute(), "absent loader candidate is not absolute")
    for name, target in runtime["links"].items():
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and str(relative) == name and ".." not in relative.parts and isinstance(target, str) and target, "invalid sealed runtime link")
    helper = runpy.run_path(str(root / PROVISIONER))
    try:
        helper["validate_runtime_aliases"](runtime)
    except ValueError as error:
        require(False, str(error))
    discovery = value["nativeDiscovery"]
    require(discovery["digest"] == digest(encoded({k: v for k, v in discovery.items() if k != "digest"})) and discovery["systemExemptions"] == ["/usr/lib", "/System/Library"], "native dependency discovery differs")
    require(discovery["inspector"]["path"] == "/usr/bin/otool" and re.fullmatch(r"sha256:[0-9a-f]{64}", discovery["inspector"]["digest"]), "native dependency inspector differs")
    images = discovery["images"]
    require(images and any(i["path"] == value["interpreter"]["path"] for i in images) and any(i["path"].endswith("/semgrep/bin/semgrep-core") for i in images), "native seeds absent")
    for image in images:
        for key in ("path", "executable"):
            p = absolute(image[key])
            require(str(p).removeprefix("/") in runtime["files"], "native image/context bytes omitted")
        for path in image["rpathStack"]:
            require(isinstance(path, str) and PurePosixPath(path).is_absolute(), "native rpath stack is not absolute")
        for dependency in image["dependencies"]:
            p = absolute(dependency["resolved"])
            if dependency["systemExempt"] is True:
                require(any(p.is_relative_to(PurePosixPath(r)) for r in discovery["systemExemptions"]), "non-system native library exempted")
            else:
                require(dependency["systemExempt"] is False and str(p).removeprefix("/") in runtime["files"], "native dependency bytes omitted")
    if live:
        require(digest(Path("/usr/bin/otool").read_bytes()) == discovery["inspector"]["digest"], "native inspector identity differs")
    if live:
        observed = helper["snapshot"](runtime["roots"], runtime["exclusions"], runtime["links"], runtime["absent"])
        require(observed == runtime, "live complete runtime closure differs")

def _ordinary_json(value):
    if isinstance(value, _JsonNumber):
        return float(value.token) if value.floating else int(value.token)
    if isinstance(value, dict):
        return {key: _ordinary_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_ordinary_json(item) for item in value]
    return value


def _semantic_record(raw_record):
    parsed = _raw_json_value(raw_record)
    require(isinstance(parsed, dict), "Semgrep record must be an object")
    return _ordinary_json(parsed)


def validate_record_bytes(repository_root, raw_record, *, expected_row=None, live=False, receipts=None):
    """Validate one original Rust-issued record without losing number spellings."""
    row = _semantic_record(raw_record)
    if expected_row is not None:
        require(row == expected_row, "raw Semgrep record differs from semantic row")
    record_digest(raw_record)
    return validate_record(repository_root, row, live=live, receipts=receipts, raw_record=raw_record)


def validate_record(repository_root, row, *, live=False, receipts=None, raw_record=None):
    root = Path(repository_root).resolve()
    if raw_record is not None:
        require(row == _semantic_record(raw_record), "raw bytes differ from supplied semantic row")
    require(row["schema"] == "legion-semgrep-provider-accuracy/1" and row["provider"] == ID and row["stage"] == "candidate" and row["scope"] == FAMILY_SCOPE and row["productionQualification"] is False, "fixture claim scope differs")
    require(row["qualificationEligible"] is True and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "fixture record unsuccessful")
    if raw_record is None:
        require(row["qualificationDigest"] == digest(encoded({k: v for k, v in row.items() if k != "qualificationDigest"})), "record digest differs")
    else:
        require(record_digest(raw_record) == row["qualificationDigest"], "record digest differs")
    child_logs = row["childLogs"]
    require([log["control"] for log in child_logs] == ["controls", "missing-tool"], "child raw log controls differ")
    for log in child_logs:
        require(log["exitCode"] == 0 and set(log["streams"]) == {"stdout", "stderr"}, "child execution failed")
        for stream, artifact in log["streams"].items():
            require(artifact["path"] == f'child-{log["control"]}.{stream}.log' and type(artifact["bytes"]) is int and artifact["bytes"] >= 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", artifact["digest"]), "child raw artifact binding differs")
            if live:
                require(receipts is not None, "child raw artifact directory absent")
                path = Path(receipts) / artifact["path"]
                require(path.is_file() and not path.is_symlink(), "child raw artifact absent/symlink")
                raw = path.read_bytes()
                require(len(raw) == artifact["bytes"] and digest(raw) == artifact["digest"], "child raw artifact differs")
    binding = row["binding"]
    source_map = sources(root)
    require(binding["sources"] == source_map and binding["sourcesDigest"] == digest(encoded(source_map)) and binding["fixture"] == HARNESS, "implementation closure differs")
    spec = next(p for p in load(root / "src/registry/providers.json")["providers"] if p["id"] == ID)
    spec.pop("benchmark", None)
    require(binding["providerSpec"] == spec and binding["providerSpecDigest"] == digest(encoded(spec)), "source provider spec differs")
    require(row["contract"] == contract(root), "packaged limited scope differs")
    cases = row["cases"]
    require([c["caseId"] for c in cases] == list(FIXTURES), "fixed six-control corpus differs")
    identities, fixture_sources = [], {}
    for case in cases:
        name = case["caseId"]
        source, rule = FIXTURES[name]
        failed, missing = name in ("operational-error", "missing-tool"), name == "missing-tool"
        require(case["source"] == {"path": "app.py", "bytes": source, "digest": digest(source.encode())} and case["expectedRule"] == rule, "source fixture differs")
        fixture_sources[name + "/app.py"] = digest(source.encode())
        inv, plan = case["inventory"], case["frozenPlan"]
        entry = {"path": "app.py", "symbols": [], "dependencies": [], "packageScripts": [], "sourceFile": True, "digest": digest(source.encode())}
        require(inv["entries"] == [entry] and inv["schemaVersion"] == 1 and inv["repositoryId"] == name, "inventory denominator differs")
        require(inv["generation"] == "filesystem:" + digest(encoded([entry])) and inv["digest"] == digest(encoded([1, name, inv["generation"], [entry]])), "inventory integrity differs")
        require(case["planDigest"] == digest(encoded(plan)) and case["planSignature"] == "hmac-sha256:" + hmac.new(b"semgrep-fixture-key", encoded(plan), hashlib.sha256).hexdigest(), "frozen plan integrity differs")
        require(plan["inventoryDigest"] == inv["digest"] and len(plan["providers"]) == 1 and plan["providers"][0]["id"] == ID, "plan scope differs")
        cfg = case["providerConfiguration"]
        require(cfg == plan["providers"][0]["configuration"] and cfg["semgrepContract"] == contract(root) and cfg["denominatorCount"] == 1 and cfg["selector"] == {"op": "sourceFilesAtLeast", "count": 1}, "frozen contract differs")
        denominator = digest(encoded([inv["digest"], cfg["selector"], [entry]]))
        require(cfg["denominatorDigest"] == denominator, "selector denominator digest differs")
        enrolled = case["runtimeEnrollment"]
        enrollment(enrolled, root, live=live)
        require(case["runtimeVerifiedBefore"] is True and case["runtimeVerifiedAfter"] is True, "runtime readback missing")
        policy = case["policy"]
        source_root = absolute(policy["cwd"])
        require(source_root.name == "source" and source_root.parent.name == name, "fixture path differs")
        run = source_root.parent / "run"
        args = list(FLAGS)
        rules_path = run / "reports" / ("semgrep-" + contract(root)["rulesDigest"].removeprefix("sha256:") + ".yml")
        args[2] = str(rules_path)
        args += ["--", "./app.py"]
        require(policy["args"] == args and policy["acceptedExitCodes"] == [0] and policy["provider"] == ID and policy["task"] == "sast" and policy["plan"] == case["planDigest"] and policy["id"] == "legion-semgrep-sdk-fixture-v1" and policy["version"] == 1, "exact SDK policy differs")
        require(policy["tool"] == enrolled["launcher"], "policy launcher differs")
        environment = policy["environment"]
        scratch_paths = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target", "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
        expected_environment = {key: str(run / value) for key, value in scratch_paths.items()}
        expected_environment.update({"HOME": str(source_root.parent.parent / "home"), "PATH": environment.get("PATH"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1", "SEMGREP_CORE_EXTRA": "-no_filter_irrelevant_rules"})
        require(environment == expected_environment and sorted(policy["environmentAllowlist"]) == sorted(["PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE", *scratch_paths, "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM", "SEMGREP_CORE_EXTRA"]), "isolated SDK environment differs")
        require(isinstance(environment["PATH"], str) and (environment["PATH"] == "" if missing else environment["PATH"].split(":")[0] == str(PurePosixPath(enrolled["launcher"]["path"]).parent)), "tool resolution PATH differs")
        require(policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 8388608, "bounded SDK limits differ")
        require(policy["wrapper"]["path"] == "/usr/bin/sandbox-exec", "native wrapper absent")
        profile = policy["profile"]
        escaped = str(source_root).replace("\\", "\\\\").replace('"', '\\"')
        text = f'(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath "{escaped}"))\n'
        require(profile["text"] == text and profile["digest"] == digest(text.encode()) and profile["receiptId"] == "sandbox:macos:" + digest(text.encode()).removeprefix("sha256:"), "authenticated DenyNetwork profile differs")
        require(case["rules"] == {"path": str(rules_path), "digest": contract(root)["rulesDigest"]}, "packaged rule binding differs")
        result, receipt = case["actualProviderResult"], case["executionReceipt"]
        require(result["provider"] == ID and result["applicable"] is True and result["complete"] is (not failed) and result["findings"] == [], "native provider result differs")
        cov = result["coverage"]
        require(cov["denominator_digest"] == denominator and cov["expected"] == 1 and cov["examined"] == (0 if failed else 1), "provider coverage differs")
        require(bool(result["coverage_gaps"]) is failed and result["details"]["executionReceipt"] == receipt, "gap/receipt projection differs")
        require(receipt["providerId"] == ID and receipt["planId"] == case["planDigest"] and receipt["taskId"] == "sast" and receipt["cwd"] == str(source_root), "SDK receipt context differs")
        require(receipt["processTree"]["started"] is (not missing), "process startup differs")
        if missing:
            require(receipt["state"] == "missing_executable" and receipt["complete"] is False and case["policyDecisions"] == [] and case["actualStdout"] == case["actualStderr"] == "" and case["actualRawReport"] is None, "missing tool became scan success")
            continue
        argv = ["-f", profile["path"], "--", policy["tool"]["path"], *args]
        require(receipt["command"]["args"] == policy["wrappedArgs"] == argv and receipt["command"]["executable"] == policy["wrapper"]["path"], "actual SDK command differs")
        require(receipt["sandbox"] == {"required": True, "receiptId": profile["receiptId"], "networkEnabled": True}, "native sandbox receipt differs")
        require(receipt["processTree"]["terminated"] is True and receipt["processTree"]["reaped"] is True, "native cleanup unproven")
        version = receipt["executable"]["version"]
        require(version["args"] == policy["versionArgs"] == argv[:4] + ["--version"] and version["qualified"] is True and version["exitCode"] == 0 and version["output"].strip() == "1.141.0", "tool version differs")
        require(receipt["executable"]["digest"] == policy["wrapper"]["digest"] and receipt["executable"]["canonicalPath"] == "/usr/bin/sandbox-exec", "wrapper identity differs")
        require(receipt["policy"]["allowed"] is True and receipt["policy"]["id"] == policy["id"] and receipt["policy"]["digest"] == digest(encoded(policy)), "actual SDK authorization differs")
        require(receipt["environmentNames"] == sorted(environment), "actual SDK environment names differ")
        decisions = case["policyDecisions"]
        require(len(decisions) == 1 and decisions[0]["allowed"] is True and decisions[0]["requestId"] == receipt["requestId"] and decisions[0]["args"] == argv and decisions[0]["acceptedExitCodes"] == [0], "observed request differs")
        decision = decisions[0]
        require(decision["environmentNames"] == sorted(environment) and decision["environmentDigest"] == digest(encoded(environment)) and decision["versionArgs"] == policy["versionArgs"] and decision["expectedDigest"] == policy["wrapper"]["digest"], "actual SDK runtime request differs")
        require(decision["requiresNetworkSandbox"] is True and decision["sandbox"] == {"id": profile["receiptId"], "network": True, "filesystemScope": str(source_root)}, "actual DenyNetwork request differs")
        for stream in ("stdout", "stderr"):
            raw = case["actual" + stream.capitalize()].encode()
            artifact = receipt[stream]
            require(artifact["immutable"] is True and artifact["bytes"] == len(raw) and artifact["digest"] == digest(raw), "actual raw artifact differs")
            rel = PurePosixPath(artifact["path"])
            require(not rel.is_absolute() and ".." not in rel.parts, "artifact escape")
        raw = json.loads(case["actualStdout"])
        require(raw == case["actualRawReport"], "raw report differs")
        if failed:
            require(receipt["exitCode"] != 0 and receipt["complete"] is False and raw["errors"], "actual operational failure became clean")
        else:
            require(receipt["exitCode"] == 0 and receipt["state"] == "completed" and receipt["complete"] is True and raw["version"] == "1.141.0" and raw["errors"] == raw["skipped_rules"] == raw["paths"]["skipped"] == [], "partial Semgrep execution accepted")
            require([p.removeprefix("./") for p in raw["paths"]["scanned"]] == ["app.py"], "selected file unexamined")
            expected = [] if rule is None else [f"{rule}|app.py|3"]
            labels = [f'{r["check_id"]}|{r["path"].removeprefix("./")}|{r["start"]["line"]}' for r in raw["results"]]
            require(labels == expected == case["actualLabels"] and result["details"]["findingsCount"] == len(expected), "actual fixed rule match differs")
            require(cov["gaps"] == [] and result["degradation"] == [], "successful fixture retained gap/degradation")
            candidates = result["details"]["candidates"]
            require(len(candidates) == len(expected), "candidate count differs")
            for candidate, match in zip(candidates, raw["results"]):
                wanted = {"id": digest(f"{rule}\0app.py\x003".encode()), "ruleId": rule, "role": "candidate-generator", "claim": match["extra"]["message"], "severityHint": "high", "evidence": [{"file": "app.py", "line": 3}], "evidenceStrength": "candidate", "verdict": "UNADJUDICATED", "adjudicationRequired": True}
                require(candidate == wanted, "candidate meaning/location differs")
        identities.append((enrolled, policy["tool"], policy["wrapper"], version["output"]))
    require(all(v == identities[0] for v in identities) and all(c["runtimeEnrollment"] == cases[0]["runtimeEnrollment"] for c in cases), "pinned runtime changed across controls")
    require(binding["fixtureSources"] == fixture_sources and binding["fixtureSourcesDigest"] == digest(encoded(fixture_sources)), "fixed corpus binding differs")
    require(row["metrics"] == {"cases": 6, "matched": 6, "mismatched": 0}, "fixture metrics differ")
    return {"provider": ID, "stage": "candidate", "status": "pass", "scope": FAMILY_SCOPE, "cases": 6, "productionQualification": False}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--receipts", type=Path, required=True)
    a = p.parse_args()
    raw_record = (a.receipts / "legacy_security_sast.json").read_bytes()
    summary = validate_record_bytes(a.root, raw_record, live=True, receipts=a.receipts)
    print("SEMGREP_PROVIDER_ACCURACY_SUMMARY " + json.dumps({"records": [summary], "modelCalls": 0}, separators=(",", ":")))

if __name__ == "__main__":
    main()
