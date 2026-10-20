#!/usr/bin/env python3
"""Validate fixed real license-checker fixture controls; never authorizes production."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

ID = "legacy.security.js-licenses"
HARNESS = "engine/crates/legion-audit/tests/license_checker_accuracy.rs"
MANIFEST = "engine/crates/legion-audit/tests/fixtures/license-checker/official-tool-files.json"
FAMILY_SCOPE = "constructed native SDK license-checker controls; two actual installed package licenses, summary candidate only"
POLICY = "legion-license-checker-fixture-policy-v1"
RULE = "legacy.js_licenses.license-checker"
NODE_PINS = {"sha256:18e387c90ab8a8400183e8bdd396376e1e875b91b4c874b894dcade7b35bf572", "sha256:0b4f059915f3bf3c6cbb02422f4a529bfb21cbbec2d29851c9a5d833f78a04f6"}
SOURCE_ROOTS = ["engine/crates/legion-audit/src", "engine/crates/legion-effects/src", "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src", "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls"]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", HARNESS, MANIFEST, ".rightgit.json", "package.json", "pnpm-lock.yaml"] + [f"engine/crates/{name}/Cargo.toml" for name in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")]


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON key")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def absolute(value):
    require(isinstance(value, str), "absolute path missing")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts and not value.startswith("//"), "unsafe retained absolute path")
    return path


def source(root, relative):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and str(path) == relative and ".." not in path.parts and "\\" not in relative, "unsafe source path")
    actual = root
    for part in path.parts:
        actual /= part
        require(not actual.is_symlink(), "source symlink")
    require(actual.is_file(), f"source absent: {relative}")
    return actual


def generated_session_provenance(relative):
    # Generated host evidence only; all other source-root files remain bound.
    return re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", relative) is not None


def source_inventory(root):
    sources = {}
    for tree in SOURCE_ROOTS:
        require((root / tree).is_dir() and not (root / tree).is_symlink(), "source root absent/unsafe")
        for path in (root / tree).rglob("*"):
            require(not path.is_symlink(), "source closure symlink")
            if path.is_file() and not generated_session_provenance(path.relative_to(root).as_posix()):
                sources[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    sources.update({name: digest(source(root, name).read_bytes()) for name in SOURCE_FILES})
    return sources


def fixture(mode):
    if mode == "malformed-manifest":
        return {"package.json": "{\n"}
    license_name = "GPL-3.0-only" if mode == "copyleft-positive" else "MIT"
    return {"package.json": '{"name":"legion-license-fixture","version":"1.0.0","license":"MIT","dependencies":{"fixture-dependency":"1.0.0"}}\n',
            "node_modules/fixture-dependency/package.json": '{"name":"fixture-dependency","version":"1.0.0","license":"' + license_name + '"}\n'}


def validate_identity(identity, manifest, live):
    provision, tool, package = (absolute(identity[key]) for key in ("toolRoot", "toolPath", "publishedPackageRoot"))
    require(tool == package / "bin/license-checker" and provision in package.parents, "published entry script outside provisioned root")
    same(identity["publishedManifest"], manifest, "official published package manifest differs")
    files = identity["files"]
    require(files and identity["filesDigest"] == digest(encoded(files)), "runtime closure digest differs")
    for name, item in files.items():
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts and str(relative) == name, "runtime relative path differs")
        if "digest" in item:
            require(set(item) == {"digest", "bytes"} and re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) and type(item["bytes"]) is int and item["bytes"] >= 0, "runtime file identity differs")
        else:
            require(set(item) == {"symlink", "canonicalTarget"}, "runtime symlink fields differ")
            target = PurePosixPath(item["canonicalTarget"])
            require(not target.is_absolute() and ".." not in target.parts, "runtime link escapes closure")
    for name, hash_value in manifest["files"].items():
        relative = str((package / name).relative_to(provision))
        require(files[relative]["digest"] == hash_value, "published package byte hash differs")
    node = identity["node"]
    node_path = absolute(node["path"])
    require(node["version"] == "22.23.2" and node["digest"] in NODE_PINS, "Node is not pinned official binary")
    if live:
        actual = {}
        for path in Path(provision).rglob("*"):
            relative = path.relative_to(str(provision)).as_posix()
            if path.is_symlink():
                target = path.resolve(strict=True)
                require(target.is_relative_to(str(provision)), "live runtime symlink escapes closure")
                actual[relative] = {"symlink": str(path.readlink()), "canonicalTarget": target.relative_to(str(provision)).as_posix()}
            elif path.is_file():
                data = path.read_bytes()
                actual[relative] = {"digest": digest(data), "bytes": len(data)}
            else:
                require(path.is_dir(), "nonregular live runtime entry")
        same(files, actual, "live tool/dependency closure differs")
        require(Path(tool).resolve().as_posix() == str(tool) and Path(node_path).resolve().as_posix() == str(node_path) and digest(Path(node_path).read_bytes()) == node["digest"], "live Node/script identity differs")
        require(Path(tool).read_bytes().splitlines()[0] == b"#!/usr/bin/env node", "published Node entrypoint differs")


def validate_record(repository_root, record, live=False):
    root = Path(repository_root).resolve()
    require(type(live) is bool and record["schema"] == "legion-license-checker-native-accuracy/1" and record["provider"] == ID, "fixed license-checker identity differs")
    require(record["scope"] == FAMILY_SCOPE and record["stage"] == "candidate" and record["outputKind"] == "candidates" and record["executionPath"] == "native-sdk-frozen-plan-real-license-checker", "bounded candidate claim differs")
    require(record["productionQualification"] is False and record["qualificationEligible"] is True and record["status"] == "pass" and record["coverageState"] == "complete" and type(record["modelCalls"]) is int and record["modelCalls"] == 0, "controls not eligible or production claim expanded")
    require(record["qualificationDigest"] == digest(encoded({key: value for key, value in record.items() if key != "qualificationDigest"})), "qualification seal differs")
    specs = parsed(source(root, "src/registry/providers.json").read_bytes())["providers"]
    matches = [item for item in specs if item["id"] == ID]
    require(len(matches) == 1, "provider missing/duplicated")
    spec = {key: value for key, value in matches[0].items() if key != "benchmark"}
    binding = record["binding"]
    same(binding["providerSpec"], spec, "sanitized provider spec differs")
    require(record["providerVersion"] == spec["providerVersion"] and binding["providerSpecDigest"] == digest(encoded(spec)) and binding["fixture"] == HARNESS, "provider/harness binding differs")
    sources = source_inventory(root)
    same(binding["sources"], sources, "source closure stale/incomplete")
    require(binding["sourcesDigest"] == digest(encoded(sources)), "source closure seal differs")
    manifest = parsed(source(root, MANIFEST).read_bytes())
    require(manifest["version"] == "25.0.1" and len(manifest["files"]) == 32 and manifest["tarballSha256"] == "sha256:e0200853f53ff27b2418fe0e3497d50a4bb2a0978abe0ef6b86c80d92fc47363" and manifest["tarball"] == "https://registry.npmjs.org/license-checker/-/license-checker-25.0.1.tgz", "official tool pin differs")
    identity = record["runtimeIdentity"]
    validate_identity(identity, manifest, live)
    cases = record["cases"]
    require([case["caseId"] for case in cases] == ["copyleft-positive", "mit-absence", "malformed-manifest", "missing-tool"], "fixed control set differs")
    fixture_sources = {}
    request_ids = []
    retained = None
    for case in cases:
        mode = case["caseId"]
        failed, missing, positive = mode == "malformed-manifest", mode == "missing-tool", mode == "copyleft-positive"
        require(case["stage"] == "candidate" and case["productionQualification"] is False and case["controlMatched"] is True, "case scope differs")
        files = fixture(mode)
        same(case["fixtureFiles"], files, "literal fixture differs")
        hashes = {name: digest(data.encode()) for name, data in files.items()}
        same(case["fixtureSources"], hashes, "fixture source hashes differ")
        fixture_sources.update({mode + "/" + name: value for name, value in hashes.items()})
        result, receipt = case["nativeResult"], case["executionReceipt"]
        same(result["details"]["executionReceipt"], receipt, "receipt detached from actual native result")
        require(result["provider"] == ID and result["applicable"] is True and result["findings"] == [], "candidate adapter adjudicated or not applicable")
        inventory, plan = case["inventory"], case["frozenPlan"]
        entries = inventory["entries"]
        require(len(entries) == 1 and entries[0]["path"] == "package.json" and entries[0]["digest"] == hashes["package.json"], "frozen package manifest denominator differs")
        require(inventory["schemaVersion"] == 1 and inventory["repositoryId"] == mode and inventory["generation"] == "filesystem:" + digest(encoded(entries)) and inventory["digest"] == digest(encoded([1, mode, inventory["generation"], entries])), "inventory seal differs")
        require(plan["inventoryDigest"] == inventory["digest"] and plan["repositoryId"] == mode and plan["inventoryGeneration"] == inventory["generation"] and case["planDigest"] == digest(encoded(plan)) and case["planSignature"] == "hmac-sha256:" + hmac.new(b"license-checker-constructed-fixture-key", encoded(plan), hashlib.sha256).hexdigest(), "frozen plan seal differs")
        require(len(plan["providers"]) == 1 and plan["providers"][0]["id"] == ID and plan["providers"][0]["version"] == spec["providerVersion"], "frozen shipped provider differs")
        configuration = plan["providers"][0]["configuration"]
        same(configuration, case["providerConfiguration"], "configuration detached from frozen plan")
        denominator = digest(encoded([inventory["digest"], configuration["selector"], entries]))
        require(configuration["denominatorCount"] == 1 and configuration["denominatorDigest"] == denominator, "frozen denominator digest differs")
        cwd = absolute(receipt["cwd"])
        base = cwd.parent.parent
        require(cwd.name == "source" and cwd.parent.name == mode and base.name == "license-checker" and base.parent.name == "legion-provider-qualification", "retained fixture root differs")
        require(retained is None or retained == base, "control roots differ")
        retained = base
        require(receipt["schemaVersion"] == 1 and receipt["providerId"] == ID and receipt["planId"] == case["planDigest"] and receipt["taskId"] == "js_licenses", "SDK identity differs")
        candidates = result["details"].get("candidates", [])
        if missing:
            require(result["complete"] is False and result["coverage_gaps"] and candidates == [] and receipt["state"] == "missing_executable" and receipt["complete"] is False and receipt["processTree"]["started"] is False and case["policyDecisions"] == [] and case["runtimeIdentityDigest"] is None and case["policyDefinition"] is None, "missing executable became clean/ran a process")
            require(receipt["stdout"] is None and receipt["stderr"] is None and case["actualStdout"] == case["actualStderr"] == "", "missing tool invented output artifacts")
            continue
        require(case["runtimeIdentityDigest"] == digest(encoded(identity)), "runtime closure changed across controls")
        policy, decisions = case["policyDefinition"], case["policyDecisions"]
        require(len(decisions) == 1 and decisions[0]["allowed"] is True, "missing/duplicate SDK admission")
        decision = decisions[0]
        require(re.fullmatch(r"legion-audit/[0-9a-f]{64}", receipt["requestId"]) and receipt["requestId"] == decision["requestId"] and receipt["receiptId"] == "receipt:" + receipt["requestId"], "real SDK request identity differs")
        request_ids.append(receipt["requestId"])
        require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["exitCode"] == 0 and receipt["signal"] is None and receipt["gaps"] == [], "actual zero-exit scanner execution incomplete")
        require(all(receipt["processTree"][key] is True for key in ("started", "terminated", "reaped")), "native process lifecycle incomplete")
        require(receipt["policyId"] == POLICY and receipt["policy"]["id"] == POLICY and receipt["policy"]["version"] == 1 and receipt["policy"]["allowed"] is True and receipt["policy"]["digest"] == digest(encoded(policy)), "actual policy receipt differs")
        require(policy["id"] == POLICY and policy["version"] == 1 and policy["provider"] == ID and policy["task"] == "js_licenses" and policy["plan"] == case["planDigest"] and policy["cwd"] == str(cwd) and policy["args"] == ["--json", "--production"] and policy["acceptedExitCodes"] == [0, 1, 2] and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 8388608, "exact scoped native policy differs")
        require(policy["runtimeIdentityDigest"] == digest(encoded(identity)), "runtime identity not admission-bound")
        require(policy["tool"]["path"] == identity["toolPath"] and policy["tool"]["digest"] == manifest["files"]["bin/license-checker"] and policy["wrapper"]["path"] == "/usr/bin/sandbox-exec", "script/wrapper identity differs")
        escaped = str(cwd).replace("\\", "\\\\").replace('"', '\\"')
        profile = '(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath "' + escaped + '"))\n'
        profile_digest = digest(profile.encode())
        profile_path = cwd.parent / "run/sandbox" / ("audit-" + profile_digest.removeprefix("sha256:") + ".sb")
        sandbox_id = "sandbox:macos:" + profile_digest.removeprefix("sha256:")
        same(policy["profile"], {"path": str(profile_path), "text": profile, "digest": profile_digest, "receiptId": sandbox_id}, "native deny-network profile differs")
        prefix = ["-f", str(profile_path), "--", identity["toolPath"]]
        require(policy["wrappedArgs"] == receipt["command"]["args"] == decision["args"] == prefix + ["--json", "--production"] and policy["versionArgs"] == receipt["executable"]["version"]["args"] == decision["versionArgs"] == prefix + ["--help"], "shipped scan/probe argv differs")
        require(receipt["command"]["executable"] == receipt["executable"]["canonicalPath"] == policy["wrapper"]["path"] and receipt["executable"]["digest"] == policy["wrapper"]["digest"], "wrapper identity detached")
        version = receipt["executable"]["version"]
        require(version["qualified"] is True and version["exitCode"] == 0 and "license-checker@25.0.1" in version["output"].splitlines(), "genuine successful version-bearing help missing")
        same(receipt["sandbox"], {"required": True, "receiptId": sandbox_id, "networkEnabled": True}, "native confinement receipt differs")
        environment = {"PATH": policy["environment"]["PATH"], "HOME": str(base / "home")}
        require(environment["PATH"].split(":")[0] == str(absolute(identity["toolRoot"]) / "bin"), "published script alias must lead exact child PATH")
        for part in environment["PATH"].split(":"): absolute(part)
        cache = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target", "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
        environment.update({name: str(cwd.parent / "run" / relative) for name, relative in cache.items()})
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONNOUSERSITE"] = "1"
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        same(policy["environment"], environment, "exact isolated native environment differs")
        same(policy["environmentAllowlist"], sorted({"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE", *cache, "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM"}), "environment allowlist differs")
        require(set(receipt["environmentNames"]) == set(environment) and decision["environmentNames"] == sorted(environment) and decision["environmentDigest"] == digest(encoded(environment)), "actual environment admission differs")
        require(decision["providerId"] == ID and decision["planId"] == case["planDigest"] and decision["taskId"] == "js_licenses" and decision["cwd"] == str(cwd) and decision["executable"] == policy["wrapper"]["path"] and decision["expectedDigest"] == policy["wrapper"]["digest"] and decision["requiresNetworkSandbox"] is True and decision["acceptedExitCodes"] == [0, 1, 2] and decision["timeoutMs"] == 120000 and decision["stdoutLimit"] == decision["stderrLimit"] == 8388608, "actual scoped SDK request differs")
        same(decision["sandbox"], {"id": sandbox_id, "network": True, "filesystemScope": str(cwd)}, "actual admission sandbox differs")
        for stream in ("stdout", "stderr"):
            item, raw = receipt[stream], case["actual" + stream.title()]
            path = PurePosixPath(item["path"])
            require(not path.is_absolute() and ".." not in path.parts and item["immutable"] is True and item["digest"] == digest(raw.encode()) and item["bytes"] == len(raw.encode()), "actual SDK output binding differs")
            if live:
                require((Path(str(cwd.parent)) / "run/artifacts" / str(path)).read_bytes() == raw.encode(), "retained output artifact absent/changed")
        raw = parsed(case["actualStdout"])
        if failed:
            require(raw == {} and "Found error" in case["actualStderr"].splitlines() and result["complete"] is False and "legacy-tool-reported-error:js_licenses" in result["coverage_gaps"] and result["details"]["findingsCount"] is None and candidates == [], "actual zero-exit read error became clean or candidate")
        else:
            require(result["complete"] is True and result["coverage_gaps"] == result["degradation"] == [], "positive/clean native coverage incomplete")
            coverage = result["coverage"]
            require(coverage["expected"] == coverage["examined"] == 1 and coverage["denominator_digest"] == denominator and coverage["gaps"] == [], "native frozen path coverage differs")
            require(set(raw) == {"legion-license-fixture@1.0.0", "fixture-dependency@1.0.0"}, "actual installed package coverage differs")
            for name, license_name, path in (("legion-license-fixture", "MIT", cwd), ("fixture-dependency", "GPL-3.0-only" if positive else "MIT", cwd / "node_modules/fixture-dependency")):
                require(raw[name + "@1.0.0"]["licenses"] == license_name and raw[name + "@1.0.0"]["path"] == str(path), "actual package license/file correspondence differs")
            require(case["actualStderr"] == "" and result["details"]["totalDeps"] == 2 and result["details"]["copyleft"] == result["details"]["findingsCount"] == int(positive) and case["actualPackageCount"] == 2, "actual tool/parser count differs")
            expected = [{"id": digest((RULE + "\0package.json\0" + "1").encode()), "ruleId": RULE, "role": "candidate-generator", "claim": "js_licenses reported 1 finding(s)", "severityHint": "high", "evidence": [{"file": "package.json", "line": 1}], "evidenceStrength": "candidate", "verdict": "UNADJUDICATED", "adjudicationRequired": True}] if positive else []
            same(candidates, expected, "actual summary candidates differ/duplicate")
            same(case["expectedCandidates"], expected, "literal candidate expectation changed")
            same(case["actualCandidates"], candidates, "candidate projection detached")
        if live:
            require(Path(str(profile_path)).read_bytes() == profile.encode() and digest(Path(policy["wrapper"]["path"]).read_bytes()) == policy["wrapper"]["digest"], "live sandbox identity differs")
        if live:
            for name, data in files.items(): require((Path(str(cwd)) / name).read_bytes() == data.encode(), "live fixture changed")
    require(len(request_ids) == len(set(request_ids)) == 3, "SDK admissions reused")
    same(binding["fixtureSources"], fixture_sources, "combined literal fixture binding differs")
    require(binding["fixtureSourcesDigest"] == digest(encoded(fixture_sources)), "combined fixture seal differs")
    require([item["mode"] for item in record["children"]] == ["controls", "missing-tool"] and all(item["exitCode"] == 0 for item in record["children"]), "genuine child terminal success missing")
    same(record["metrics"], {"cases": 4, "matched": 4, "mismatched": 0}, "control metrics differ")
    return {"provider": ID, "stage": "candidate", "qualificationDigest": record["qualificationDigest"], "scope": FAMILY_SCOPE, "productionQualification": False, "cases": 4, "matched": 4, "mismatched": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    path = args.receipts / "legacy_security_js-licenses.json"
    require(path.is_file() and not path.is_symlink(), "retained license control record missing")
    result = validate_record(args.root, parsed(path.read_bytes()), live=True)
    print("LICENSE_CHECKER_PROVIDER_ACCURACY_SUMMARY " + json.dumps({"records": [result], "modelCalls": 0}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
