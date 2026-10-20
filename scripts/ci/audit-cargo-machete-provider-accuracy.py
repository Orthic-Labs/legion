#!/usr/bin/env python3
"""Fixed cargo-machete constructed SDK fixture evidence; never qualifies owner admission."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import runpy

PROVIDER = "legacy.quality.rust-unused-deps"
HARNESS = "engine/crates/legion-audit/tests/real_cargo_machete_accuracy.rs"
SCOPE = "constructed-native-sdk-fixture"
ROOTS = ["engine/crates/legion-audit/src", "engine/crates/legion-effects/src",
         "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src",
         "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls"]
FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml",
         "engine/crates/legion-audit/Cargo.toml", "engine/crates/legion-effects/Cargo.toml",
         "engine/crates/legion-provider-sdk/Cargo.toml", "engine/crates/legion-contracts/Cargo.toml",
         "engine/crates/legion-rules/Cargo.toml", HARNESS]
PINS = {"sha256:72355383848acb154060e6fea2d5b7d58a825ed49fef157b46a6fe25180f8638":
        "sha256:76ce4dc236df8204d8c110a4d1164a3abe8240fd622ab7016bf02f901d113167",
        "sha256:fd0c0dbcc9db0c1b8745fe9dc4f273d838b04391c6e487d1146957bf687a9703":
        "sha256:e1cfbe4e076a040b6fa394f52e94a3895ff4078a1dd435ab5ed641f145a4815e"}
CLEAN = "cargo-machete didn't find any unused dependencies in this directory. Good job!\n"
PROGRESS = "Analyzing dependencies of crates in this directory...\nDone!\n"
POSITIVE = ('cargo-machete found the following unused dependencies in this directory:\n'
            'machete-probe -- ./Cargo.toml:\n\tmachete-helper\n\n'
            'If you believe cargo-machete has detected an unused dependency incorrectly,\n'
            'you can add the dependency to the list of dependencies to ignore in the\n'
            '`[package.metadata.cargo-machete]` section of the appropriate Cargo.toml.\n'
            'For example:\n\n[package.metadata.cargo-machete]\nignored = ["prost"]\n\n')


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load(path):
    def pairs(rows):
        require(len(dict(rows)) == len(rows), "duplicate JSON fields")
        return dict(rows)
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "non-JSON number"))


def generated_session_provenance(relative):
    # Generated host evidence only; all other source-root files remain bound.
    return re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", relative) is not None


def source_files(root):
    result = {}
    for relative in ROOTS + FILES:
        base = root / relative
        require(base.exists() and not base.is_symlink(), "source binding missing/unsafe: " + relative)
        for path in base.rglob("*") if base.is_dir() else [base]:
            require(not path.is_symlink(), "symlink source binding")
            if path.is_file() and not generated_session_provenance(path.relative_to(root).as_posix()):
                result[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    return result


def fixtures(control):
    error = control == "analysis-error"
    files = {"Cargo.toml": "[package\n" if error else '[package]\nname = "machete-probe"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\nmachete-helper = { path = "machete-helper" }\n[workspace]\nmembers = ["machete-helper"]\n',
             "Cargo.lock": '# This file is manually generated for offline fixture metadata.\nversion = 3\n\n[[package]]\nname = "machete-helper"\nversion = "0.1.0"\n\n[[package]]\nname = "machete-probe"\nversion = "0.1.0"\ndependencies = [\n "machete-helper",\n]\n',
             ".cargo/config.toml": "[net]\noffline = true\n",
             "src/lib.rs": "pub fn value() -> u8 { machete_helper::value() }\n" if control in ("absence", "missing-tool") else "pub fn value() -> u8 { 7 }\n"}
    if not error:
        files.update({"machete-helper/Cargo.toml": '[package]\nname = "machete-helper"\nversion = "0.1.0"\nedition = "2021"\n',
                      "machete-helper/src/lib.rs": "pub fn value() -> u8 { 7 }\n"})
    return files


def retained_item(directory, item, raw):
    relative = PurePosixPath(item["file"])
    require(not relative.is_absolute() and ".." not in relative.parts and str(relative) == item["file"], "unsafe retained artifact")
    require(item["bytes"] == len(raw) and item["sha256"] == digest(raw), "retained artifact identity differs")
    if directory is not None:
        path = directory / str(relative)
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw, "retained artifact bytes differ")


def validate_record(repository_root, row, live=False, receipts=None):
    root = Path(repository_root).resolve()
    api = runpy.run_path(str(root / "scripts/ci/audit-real-provider-accuracy.py"))
    require(row["schema"] == "legion-cargo-machete-accuracy/1" and row["kind"] == "cargo-machete-provider-constructed"
            and row["provider"] == PROVIDER and row["claimScope"] == SCOPE
            and row["productionQualification"] is False and row["selfProducerQualification"] is False
            and row["modelCalls"] == 0 and type(row["modelCalls"]) is int and row["status"] == "pass"
            and row["executionPath"] == "native-sdk-frozen-plan-real-cargo-machete"
            and row["admissionScope"] == "explicit constructed SDK authorizer; no production CLI owner-admission claim", "fixed record identity/scope differs")
    unsigned = {key: value for key, value in row.items() if key != "qualificationDigest"}
    require(row["qualificationDigest"] == digest(canonical(unsigned)), "original self digest differs")
    registry = load(root / "src/registry/providers.json")["providers"]
    spec = next(item for item in registry if item["id"] == PROVIDER).copy()
    spec.pop("benchmark")
    bound = row["binding"]
    require(bound["fixture"] == HARNESS and bound["providerSpec"] == spec
            and bound["providerSpecDigest"] == digest(canonical(spec)) and row["providerVersion"] == spec["providerVersion"], "shipped provider specification differs")
    sources = source_files(root)
    require(bound["sources"] == sources and bound["sourcesDigest"] == digest(canonical(sources)), "full implementation source closure differs")
    cases = row["cases"]
    controls = ["positive", "absence", "analysis-error", "missing-tool"]
    require([case["caseId"] for case in cases] == controls, "fixed controls missing/duplicated/reordered")
    all_fixtures, identities = {}, []
    for case, control in zip(cases, controls):
        positive, failed, missing = control == "positive", control == "analysis-error", control == "missing-tool"
        files = fixtures(control)
        hashes = {path: digest(text.encode()) for path, text in files.items()}
        require(case["provider"] == PROVIDER and case["control"] == control and case["matched"] is True
                and case["fixtureFiles"] == files and case["fixtureSources"] == hashes, "source-owned fixture differs")
        all_fixtures.update({control + "/" + key: value for key, value in hashes.items()})
        inventory, planned, result = case["inventory"], case["frozenProvider"], case["nativeResult"]
        require(case["fullProviderResult"] == result and result["provider"] == PROVIDER and result["applicable"] is True, "actual full provider result differs")
        entries = [{"path": path, "symbols": [], "dependencies": ["machete-helper"] if path == "Cargo.toml" and not failed else [], "packageScripts": [], "sourceFile": path.endswith(".rs"), "digest": hashes[path]} for path in sorted(files)]
        require(inventory["entries"] == entries and inventory["schemaVersion"] == 1 and inventory["repositoryId"] == control
                and inventory["generation"] == "filesystem:" + digest(canonical(entries))
                and inventory["digest"] == digest(canonical([1, control, inventory["generation"], entries])), "actual inventory binding differs")
        selected = [item for item in entries if item["path"].endswith("Cargo.toml") or item["path"].endswith(".rs")]
        denominator = digest(canonical([inventory["digest"], spec["selector"], selected]))
        require(case["selectedPaths"] == [item["path"] for item in selected]
                and planned["id"] == PROVIDER and planned["version"] == spec["providerVersion"]
                and planned["configuration"]["selector"] == spec["selector"]
                and planned["configuration"]["denominatorCount"] == len(selected)
                and planned["configuration"]["denominatorDigest"] == denominator
                and re.fullmatch(r"sha256:[0-9a-f]{64}", case["planDigest"]), "shipped selector/denominator differs")
        plan = case["frozenPlan"]
        require(plan["schemaVersion"] == 1 and plan["repositoryId"] == control
                and plan["inventoryGeneration"] == inventory["generation"] and plan["inventoryDigest"] == inventory["digest"]
                and plan["providers"] == [planned] and plan["excludedConditionalProviders"] == []
                and case["planDigest"] == digest(canonical(plan)), "actual frozen plan identity differs")
        owner_policy = {"externalProcesses": "owner-admission-required", "admissionStatus": "unavailable", "effectiveMode": "deny-external"}
        require(plan["bounds"] == {"executionPolicy": owner_policy,
                "executionPolicyIdentity": {"id": "audit-native-owner-admission-v1", "version": 1, "digest": digest(canonical(owner_policy))}},
                "frozen production admission boundary changed")
        require(planned["role"] == spec["role"] and planned["phase"] == spec["phase"] and planned["dependencies"] == spec["dependsOn"]
                and planned["configuration"]["runner"] == spec["runner"] and planned["cleanClaim"] == spec["cleanClaim"], "shipped provider runner/role differs")
        coverage = result["coverage"]
        require(case["coverage"] == coverage and coverage["expected"] == len(selected)
                and coverage["denominator_digest"] == denominator, "coverage identity differs")
        receipt = case["executionReceipt"]
        require(receipt == result["details"]["executionReceipt"] and not result["details"].get("candidates", []), "actual SDK receipt/output stage differs")
        require(len(result["findings"]) == int(positive), "unexpected native finding")
        if missing:
            require(case["expected"] == {"complete": False, "findingCount": 0, "executionState": "missing_executable"}
                    and result["complete"] is False and result["coverage_gaps"] and coverage["examined"] == 0
                    and receipt["state"] == "missing_executable" and receipt["complete"] is False
                    and receipt["stdout"] is None and receipt["stderr"] is None and receipt["executable"] is None and receipt["policy"] is None
                    and not any(receipt["processTree"][key] for key in ("started", "terminated", "hardKilled", "reaped"))
                    and receipt["exitCode"] is None and receipt["signal"] is None and case["retainedArtifacts"] is None and case["actualStdout"] is None and case["actualStderr"] is None
                    and case["toolIdentity"] is None and case["policyDefinition"] is None and case["policyDecisions"] == [], "missing tool was executed or became clean")
            continue
        require(case["locatorPrecision"] == "aggregate fallback anchor is first selected path, not exact diagnostic locus", "aggregate locator precision overstated")
        require(case["expected"] == {"complete": not failed, "findingCount": int(positive), "findingsCount": 1 if positive else None,
                "ruleId": "legacy.cargo_unused_deps.cargo-machete", "aggregateFallbackAnchor": selected[0]["path"]}, "fixed case expectations differ")
        policy, identity = case["policyDefinition"], case["toolIdentity"]
        tool = api["executable"](policy["tool"]["path"], policy["tool"]["digest"], live=live)
        wrapper = api["executable"](policy["wrapper"]["path"], policy["wrapper"]["digest"], live=live)
        require(tool.name == "cargo-machete" and wrapper == PurePosixPath("/usr/bin/sandbox-exec")
                and identity["path"] == str(tool) and identity["binarySha256"] == policy["tool"]["digest"] == identity["officialBinarySha256"]
                and PINS.get(identity["officialAssetSha256"]) == identity["binarySha256"], "actual official binary pin differs")
        runtime = identity["cargoRuntime"]
        cargo = api["executable"](runtime["path"], runtime["binarySha256"], live=live)
        require(cargo.name == "cargo" and runtime["versionStdout"].startswith("cargo 1.98.0 ") and runtime["versionStderr"] == ""
                and runtime["exitCode"] == 0 and runtime["signal"] is None, "actual native Cargo runtime probe differs")
        cwd = PurePosixPath(policy["cwd"])
        require(cwd.is_absolute() and ".." not in cwd.parts and cwd.name == "source" and cwd.parent.name == control, "fixture cwd differs")
        run = cwd.parent / "run"
        escaped = str(cwd).replace("\\", "\\\\").replace('"', '\\"')
        text = f'(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath "{escaped}"))\n'
        profile_hash = digest(text.encode()).removeprefix("sha256:")
        profile = run / "sandbox" / ("audit-" + profile_hash + ".sb")
        sandbox = "sandbox:macos:" + profile_hash
        require(policy["profile"] == {"path": str(profile), "text": text, "digest": digest(text.encode()), "receiptId": sandbox}, "native sandbox profile differs")
        if live:
            require(profile.is_absolute() and not Path(profile).is_symlink() and Path(profile).read_text() == text, "live sandbox profile differs")
        prefix = ["-f", str(profile), "--", str(tool)]
        require(policy["id"] == "legion-real-cargo-machete-qualification-v1" and policy["version"] == 1
                and policy["provider"] == PROVIDER and policy["task"] == "cargo_unused_deps" and policy["plan"] == case["planDigest"]
                and policy["args"] == ["--with-metadata"] and policy["wrappedArgs"] == prefix + ["--with-metadata"]
                and policy["versionArgs"] == prefix + ["--version"] and policy["acceptedExitCodes"] == [0, 1]
                and policy["artifactRequestId"] == "legion-audit/<64 lowercase hex>; one admission only"
                and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 8388608
                and policy["sandbox"] == "native-macos-deny-network-production-linter-contract", "exact constructed SDK policy differs")
        environment = {"PATH": policy["environment"]["PATH"], "HOME": str(cwd.parent.parent / "home")}
        require(environment["PATH"].split(":")[0] == str(cargo.parent), "actual nested Cargo PATH differs")
        for part in environment["PATH"].split(":"):
            path = PurePosixPath(part)
            require(path.is_absolute() and ".." not in path.parts and str(path) == part, "noncanonical PATH entry")
        cache = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target",
                 "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
        environment.update({key: str(run / value) for key, value in cache.items()})
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONNOUSERSITE"] = "1"
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        require(policy["environment"] == environment and policy["environmentAllowlist"] == sorted(set(["PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"] + list(cache) + ["PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM"])), "exact admitted environment differs")
        api["native"](receipt, policy["id"], policy, canonical)
        decision, = case["policyDecisions"]
        version = receipt["executable"]["version"]
        require(identity["version"] == version["output"] and version["output"].strip() == "0.9.1" and version["args"] == prefix + ["--version"]
                and receipt["exitCode"] == int(positive) and receipt["signal"] is None
                and re.fullmatch(r"legion-audit/[0-9a-f]{64}", receipt["requestId"])
                and receipt["receiptId"] == "receipt:" + receipt["requestId"]
                and receipt["command"]["executable"] == receipt["executable"]["canonicalPath"] == str(wrapper)
                and receipt["executable"]["digest"] == policy["wrapper"]["digest"]
                and receipt["executable"]["digestState"] == "sealed"
                and receipt["environmentNames"] == receipt["command"]["environmentNames"] == sorted(environment)
                and receipt["command"]["redactedArgumentIndexes"] == receipt["command"]["redactedEnvironmentNames"] == [], "native process/version linkage differs")
        require(decision["allowed"] is True and decision["requestId"] == receipt["requestId"]
                and receipt["providerId"] == decision["providerId"] == PROVIDER
                and receipt["planId"] == decision["planId"] == case["planDigest"]
                and receipt["taskId"] == decision["taskId"] == "cargo_unused_deps"
                and receipt["cwd"] == decision["cwd"] == str(cwd)
                and receipt["command"]["args"] == decision["args"] == prefix + ["--with-metadata"]
                and decision["versionArgs"] == prefix + ["--version"]
                and decision["executable"] == str(wrapper) and decision["expectedDigest"] == policy["wrapper"]["digest"]
                and decision["acceptedExitCodes"] == [0, 1] and decision["timeoutMs"] == 120000
                and decision["stdoutLimit"] == decision["stderrLimit"] == 8388608
                and decision["environmentNames"] == sorted(environment) and decision["environmentDigest"] == digest(canonical(environment))
                and decision["requiresNetworkSandbox"] is True
                and decision["sandbox"] == {"id": sandbox, "network": True, "filesystemScope": str(cwd)}
                and receipt["sandbox"] == {"required": True, "receiptId": sandbox, "networkEnabled": True}, "exact SDK admission linkage differs")
        out, err = case["actualStdout"], case["actualStderr"]
        for stream, data in (("stdout", out), ("stderr", err)):
            api["artifact"](receipt[stream], data)
            require(case["retainedArtifacts"][stream]["file"] == control + "/" + stream + ".log", "fixed retained stream path differs")
            retained_item(receipts, case["retainedArtifacts"][stream], data.encode())
        if failed:
            require(result["complete"] is False and "cargo-machete-analysis-unproven" in result["coverage_gaps"]
                    and out == CLEAN and err.startswith("Analyzing dependencies of crates in this directory...\nerror when handling ./Cargo.toml:")
                    and err.endswith("\nDone!\n") and "[package" in err and result["details"]["findingsCount"] is None, "actual swallowed manifest error became clean")
        else:
            require(result["complete"] is True and result["status"] in ("ok", "complete") and result["coverage_gaps"] == result["degradation"] == []
                    and coverage["expected"] == coverage["examined"] == len(selected) and coverage["gaps"] == []
                    and out == (POSITIVE if positive else CLEAN) and err == PROGRESS
                    and result["details"]["findingsCount"] == (1 if positive else None), "complete case coverage/raw semantic class differs")
        if positive:
            rule, anchor = "legacy.cargo_unused_deps.cargo-machete", selected[0]["path"]
            identifier = digest(f"{rule}\0{anchor}\0{1}".encode())
            require(result["findings"] == [{"id": identifier, "severity": "low"}]
                    and result["details"]["findingEvidence"] == {identifier: {"ruleId": rule, "path": anchor, "line": 1, "message": "cargo_unused_deps reported 1 finding(s)"}}
                    and result["details"]["findingLocations"] == {identifier: [anchor + ":1"]}, "actual aggregate native finding differs")
        identities.append((identity, policy["wrapper"]))
    require(all_fixtures == bound["fixtureSources"] and bound["fixtureSourcesDigest"] == digest(canonical(all_fixtures)), "whole staged fixture corpus differs")
    require(len({canonical(item) for item in identities}) == 1, "actual tool/runtime changed between controls")
    require(row["metrics"] == {"cases": 4, "matched": 4, "mismatched": 0}, "fixed control metrics differ")
    children = row["retainedChildProcess"]
    require(len(children) == 2, "actual child process evidence absent")
    case_parts = []
    for child, name in zip(children, ("child", "missing-tool-child")):
        require(child["schema"] == "legion-cargo-machete-child-execution/1" and child["productionQualification"] is False
                and child["status"]["success"] is True and child["status"]["exitCode"] == 0 and child["status"]["signal"] is None, "fixture child failed")
        for stream in ("stdout", "stderr"):
            item = child[stream]
            require(item["file"] == name + "." + stream + ".log", "child stream identity differs")
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", item["sha256"]) and type(item["bytes"]) is int and item["bytes"] >= 0, "child stream digest/size absent")
            if receipts is not None:
                raw = (receipts / item["file"]).read_bytes()
                retained_item(receipts, item, raw)
                if stream == "stdout":
                    for line in raw.decode().splitlines():
                        if "CARGO_MACHETE_CASE " in line:
                            case_parts.append(json.loads(line.split("CARGO_MACHETE_CASE ", 1)[1]))
    if receipts is not None:
        require(case_parts == cases, "original record case bytes differ from retained actual child emissions")
    return {"provider": PROVIDER, "stage": "finding", "coverageState": "complete", "qualificationDigest": row["qualificationDigest"], "metrics": row["metrics"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    path = args.receipts / "cargo_unused_deps.json"
    record = load(path)
    validated = validate_record(args.root, record, live=True, receipts=args.receipts)
    print("CARGO_MACHETE_PROVIDER_ACCURACY_SUMMARY " + canonical({"records": [validated], "modelCalls": 0}).decode())


if __name__ == "__main__":
    main()
