#!/usr/bin/env python3
"""Fixed Rust outdated SDK fixture adapter; validates retained real run responses only."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import runpy

PROVIDER = "legacy.stack.rust-outdated"
HARNESS = "engine/crates/legion-audit/tests/real_rust_outdated_accuracy.rs"
SCOPE = "constructed-native-sdk-fixture"
ROOTS = ["engine/crates/legion-audit/src", "engine/crates/legion-effects/src",
         "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src",
         "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls"]
FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml",
         "engine/crates/legion-audit/Cargo.toml", "engine/crates/legion-effects/Cargo.toml",
         "engine/crates/legion-provider-sdk/Cargo.toml", "engine/crates/legion-contracts/Cargo.toml",
         "engine/crates/legion-rules/Cargo.toml", HARNESS]
PINS = {"sha256:c3a3ca56a748d94fdaa1f208c641685d996ee1c4954cd4fbe358b7c06a2186a5":
        "sha256:22003be477d106e10c285d11e677b680859fc72d1c0035fe599b3755ede231a8",
        "sha256:945b64728ae9021be49a70346424da7634d889f181f2d33af64c7bf95265f6d3":
        "sha256:63a2f5ffe56c7c7ad0e21eba87e4dcf7ebd757bc376c16d534caaa2d82ac127b"}
VOID = {"1.0.1": "bf1a31caf5a37d644b05946ac69108e2b39917aa5c203fd33eaf5b99adf8d2d2",
        "1.0.2": "6a02e4885ed3bc0f2de90ea6dd45ebcbb66dacffe03547fadbb0eeae2770887d"}


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def parsed(raw):
    def pairs(items):
        require(len(dict(items)) == len(items), "duplicate JSON fields")
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def load(path):
    return parsed(path.read_bytes())


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
    version = "1.0.2" if control in ("absence", "missing-tool") else "1.0.1"
    manifest = "[package\n" if control == "analysis-error" else ('[package]\nname = "outdated-probe"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\nvoid = "=' + version + '"\n')
    lock = ('# This file is manually generated from registry package metadata.\nversion = 4\n\n[[package]]\nname = "outdated-probe"\nversion = "0.1.0"\ndependencies = [\n "void",\n]\n\n[[package]]\nname = "void"\nversion = "' + version + '"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + VOID[version] + '"\n')
    files = {"Cargo.toml": manifest, "Cargo.lock": lock, "src/lib.rs": "pub fn value() {}\n"}
    if control == "uncovered-lock":
        files["extra/Cargo.lock"] = "# independently selected lock fixture\nversion = 3\n"
    return files


def retained_item(directory, item, raw):
    relative = PurePosixPath(item["file"])
    require(not relative.is_absolute() and ".." not in relative.parts and str(relative) == item["file"], "unsafe retained artifact")
    require(item["bytes"] == len(raw) and type(item["bytes"]) is int and item["sha256"] == digest(raw), "retained artifact identity differs")
    if directory is not None:
        path = directory / str(relative)
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw, "retained artifact bytes differ")


def validate_record(repository_root, row, live=False, receipts=None):
    root = Path(repository_root).resolve()
    api = runpy.run_path(str(root / "scripts/ci/audit-real-provider-accuracy.py"))
    require(row["schema"] == "legion-rust-outdated-sdk-accuracy/1" and row["kind"] == "rust-outdated-provider-constructed"
            and row["provider"] == PROVIDER and row["claimScope"] == SCOPE and row["test"] == "real_rust_outdated_accuracy"
            and row["productionQualification"] is False and row["selfProducerQualification"] is False
            and type(row["modelCalls"]) is int and row["modelCalls"] == 0 and row["status"] == "pass"
            and row["executionPath"] == "native-sdk-frozen-plan-real-cargo-outdated"
            and row["admissionScope"] == "explicit constructed SDK authorizer; no production CLI owner-admission claim", "fixed fixture identity/scope differs")
    require(row["qualificationDigest"] == digest(canonical({key: value for key, value in row.items() if key != "qualificationDigest"})), "original self digest differs")
    spec = next(item for item in load(root / "src/registry/providers.json")["providers"] if item["id"] == PROVIDER).copy()
    spec.pop("benchmark")
    bound = row["binding"]
    require(bound["fixture"] == HARNESS and bound["providerSpec"] == spec and bound["providerSpecDigest"] == digest(canonical(spec))
            and row["providerVersion"] == spec["providerVersion"], "shipped provider spec differs")
    sources = source_files(root)
    require(bound["sources"] == sources and bound["sourcesDigest"] == digest(canonical(sources)), "full implementation source closure differs")
    controls = ["positive", "absence", "analysis-error", "uncovered-lock", "missing-tool"]
    require([case["caseId"] for case in row["cases"]] == controls, "fixed controls missing/duplicated/reordered")
    all_fixtures, identities = {}, []
    for case, control in zip(row["cases"], controls):
        positive, failed, missing, uncovered = control in ("positive", "uncovered-lock"), control == "analysis-error", control == "missing-tool", control == "uncovered-lock"
        files = fixtures(control)
        hashes = {path: digest(text.encode()) for path, text in files.items()}
        require(case["provider"] == PROVIDER and case["control"] == control and case["matched"] is True
                and case["fixtureFiles"] == files and case["fixtureSources"] == hashes, "source-owned fixture differs")
        all_fixtures.update({control + "/" + key: value for key, value in hashes.items()})
        inventory, planned, result = case["inventory"], case["frozenProvider"], case["nativeResult"]
        require(case["fullProviderResult"] == result and result["provider"] == PROVIDER and result["applicable"] is True, "actual full ProviderResult differs")
        entries = [{"path": path, "symbols": [], "dependencies": ["void"] if path == "Cargo.toml" and not failed else [], "packageScripts": [], "sourceFile": path.endswith(".rs"), "digest": hashes[path]} for path in sorted(files)]
        require(inventory["entries"] == entries and inventory["schemaVersion"] == 1 and inventory["repositoryId"] == control
                and inventory["generation"] == "filesystem:" + digest(canonical(entries))
                and inventory["digest"] == digest(canonical([1, control, inventory["generation"], entries])), "actual frozen inventory differs")
        selected = [item for item in entries if item["path"].endswith("Cargo.lock")]
        denominator = digest(canonical([inventory["digest"], spec["selector"], selected]))
        require(case["selectedPaths"] == [item["path"] for item in selected] and planned["id"] == PROVIDER
                and planned["version"] == spec["providerVersion"] and planned["configuration"]["selector"] == spec["selector"]
                and planned["configuration"]["denominatorCount"] == len(selected)
                and planned["configuration"]["denominatorDigest"] == denominator, "shipped selector/denominator differs")
        plan = case["frozenPlan"]
        require(plan["schemaVersion"] == 1 and plan["repositoryId"] == control and plan["inventoryGeneration"] == inventory["generation"]
                and plan["inventoryDigest"] == inventory["digest"] and plan["providers"] == [planned]
                and plan["excludedConditionalProviders"] == [] and case["planDigest"] == digest(canonical(plan)), "full frozen plan differs")
        owner_policy = {"externalProcesses": "owner-admission-required", "admissionStatus": "unavailable", "effectiveMode": "deny-external"}
        require(plan["bounds"] == {"executionPolicy": owner_policy, "executionPolicyIdentity": {"id": "audit-native-owner-admission-v1", "version": 1, "digest": digest(canonical(owner_policy))}}, "production admission boundary changed")
        require(planned["role"] == spec["role"] and planned["phase"] == spec["phase"] and planned["dependencies"] == spec["dependsOn"]
                and planned["configuration"]["runner"] == spec["runner"] and planned["cleanClaim"] == spec["cleanClaim"], "shipped provider runner/role differs")
        coverage, receipt = result["coverage"], case["executionReceipt"]
        require(case["coverage"] == coverage and coverage["expected"] == len(selected) and coverage["denominator_digest"] == denominator
                and coverage["gaps"] == result["coverage_gaps"] and receipt == result["details"]["executionReceipt"]
                and not result["details"].get("candidates", []), "actual coverage/receipt stage differs")
        require(len(result["findings"]) == int(positive), "actual finding count differs")
        if missing:
            require(case["expected"] == {"complete": False, "findingCount": 0, "executionState": "missing_executable"}
                    and result["complete"] is False and result["coverage_gaps"] and coverage["examined"] == 0
                    and receipt["state"] == "missing_executable" and receipt["complete"] is False and receipt["exitCode"] is None and receipt["signal"] is None
                    and receipt["stdout"] is None and receipt["stderr"] is None and receipt["executable"] is None and receipt["policy"] is None
                    and not any(receipt["processTree"][key] for key in ("started", "terminated", "hardKilled", "reaped"))
                    and case["retainedArtifacts"] is None and case["actualStdout"] is None and case["actualStderr"] is None
                    and case["toolIdentity"] is None and case["policyDefinition"] is None and case["policyDecisions"] == [], "missing tool executed or became clean")
            continue
        policy, identity = case["policyDefinition"], case["toolIdentity"]
        tool = api["executable"](policy["tool"]["path"], policy["tool"]["digest"], live=live)
        wrapper = api["executable"](policy["wrapper"]["path"], policy["wrapper"]["digest"], live=live)
        require(tool.name == "cargo-outdated" and wrapper == PurePosixPath("/usr/bin/sandbox-exec") and identity["path"] == str(tool)
                and identity["binarySha256"] == identity["officialBinarySha256"] == policy["tool"]["digest"]
                and PINS.get(identity["officialAssetSha256"]) == identity["binarySha256"], "official actual tool pin differs")
        runtime = identity["cargoRuntime"]
        cargo = api["executable"](runtime["path"], runtime["binarySha256"], live=live)
        require(cargo.name == "cargo" and runtime["versionStdout"].startswith("cargo 1.98.0 ") and runtime["versionStderr"] == ""
                and runtime["exitCode"] == 0 and runtime["signal"] is None, "actual Cargo runtime probe differs")
        cwd = PurePosixPath(policy["sourceRoot"])
        require(cwd.is_absolute() and ".." not in cwd.parts and cwd.name == "source" and cwd.parent.name == control, "fixture cwd differs")
        run = cwd.parent / "run"
        execution_cwd = run / "rust-outdated-resolution/source"
        require(policy["cwd"] == str(execution_cwd), "isolated resolution cwd differs")
        resolution = result["details"]["rustOutdatedResolution"]
        rustc_identity = resolution["runtime"]["rustc"]
        rustc = api["executable"](rustc_identity["path"], rustc_identity["digest"], live=live)
        require(rustc.name == "rustc" and rustc.parent == cargo.parent, "native rustc escaped enrolled Cargo toolchain")
        postimage = resolution["postimage"]
        require(isinstance(postimage, dict) and set(postimage) == set(hashes)
                and all(re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in postimage.values())
                and all(postimage[path] == value for path, value in hashes.items() if path != "Cargo.lock"), "isolated resolution changed another copied source")
        deltas = [{"path": path, "beforeDigest": hashes[path], "afterDigest": postimage[path]}
                  for path in sorted(hashes) if hashes[path] != postimage[path]]
        require(resolution == {"sourceRoot": str(cwd), "sourceCwd": str(cwd),
                "executionRoot": str(execution_cwd), "executionCwd": str(execution_cwd),
                "inventoryDigest": inventory["digest"], "preimage": hashes, "preimageDigest": digest(canonical(hashes)),
                "postimage": postimage, "postimageError": None, "allowedChangedPath": "Cargo.lock", "deltas": deltas,
                "sourceUnchanged": True, "runtime": {"cargo": {"path": str(cargo), "digest": runtime["binarySha256"]}, "rustc": rustc_identity},
                "runtimeUnchanged": True, "valid": True}, "exact frozen-source resolution mapping differs")
        if live:
            for relative in hashes:
                source, copied = Path(cwd / relative), Path(execution_cwd / relative)
                require(source.is_file() and source.resolve(strict=True) == source and digest(source.read_bytes()) == hashes[relative]
                        and copied.is_file() and copied.resolve(strict=True) == copied and digest(copied.read_bytes()) == postimage[relative]
                        and (source.stat().st_dev, source.stat().st_ino) != (copied.stat().st_dev, copied.stat().st_ino), "live frozen source/copy bytes or identity differ")
            paths = list(Path(execution_cwd).rglob("*"))
            require(not any(path.is_symlink() for path in paths)
                    and {path.relative_to(Path(execution_cwd)).as_posix() for path in paths if path.is_file()} == set(hashes), "live copy acquired extra or aliased files")
        escaped = str(cwd).replace("\\", "\\\\").replace('"', '\\"')
        text = f'(version 1)\n(allow default)\n(allow network*)\n(allow file-read* (subpath "{escaped}"))\n(deny file-write* (subpath "{escaped}"))\n'
        profile_hash = digest(text.encode()).removeprefix("sha256:")
        profile = run / "sandbox" / ("audit-" + profile_hash + ".sb")
        sandbox = "sandbox:macos:" + profile_hash
        require(policy["profile"] == {"path": str(profile), "text": text, "digest": digest(text.encode()), "receiptId": sandbox}, "production sandbox profile differs")
        if live:
            require(not Path(profile).is_symlink() and Path(profile).read_text() == text, "live sandbox profile differs")
        prefix = ["-f", str(profile), "--", str(tool)]
        args, version_args = ["outdated", "--format", "json", "--root-deps-only"], ["outdated", "--version"]
        require(policy["id"] == "legion-rust-outdated-constructed-fixture-v1" and policy["version"] == 1 and policy["provider"] == PROVIDER
                and policy["task"] == "cargo_outdated" and policy["plan"] == case["planDigest"]
                and policy["args"] == args and policy["wrappedArgs"] == prefix + args and policy["versionArgs"] == prefix + version_args
                and policy["acceptedExitCodes"] == [0] and policy["artifactRequestId"] == "legion-audit/<64 lowercase hex>; one admission only"
                and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 8388608
                and policy["sandbox"] == "native-macos-allow-network-deny-project-write", "exact constructed policy differs")
        environment = {"PATH": policy["environment"]["PATH"], "HOME": str(run / "home"), "USERPROFILE": str(run / "home"),
                       "CARGO_HOME": str(run / "cache/cargo-home"), "CARGO": str(cargo), "RUSTC": str(rustc)}
        require(environment["PATH"].split(":")[0] == str(cargo.parent), "actual toolchain PATH differs")
        for part in environment["PATH"].split(":"):
            require(PurePosixPath(part).is_absolute() and ".." not in PurePosixPath(part).parts, "noncanonical PATH entry")
        cache = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target", "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
        environment.update({key: str(run / value) for key, value in cache.items()})
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONNOUSERSITE"] = "1"
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        require(policy["environment"] == environment and policy["environmentAllowlist"] == sorted(set(["PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE", "CARGO_HOME", "CARGO", "RUSTC"] + list(cache) + ["PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM"])), "exact admitted environment differs")
        require(receipt["policyId"] == policy["id"] and receipt["policy"]["allowed"] is True and receipt["policy"]["id"] == policy["id"]
                and receipt["policy"]["version"] == 1 and receipt["policy"]["digest"] == digest(canonical(policy)), "SDK policy receipt differs")
        version = receipt["executable"]["version"]
        require(version["qualified"] is True and version["exitCode"] == 0 and version["args"] == prefix + version_args
                and identity["version"] == version["output"] and re.search(r"(?<![0-9.])0\.19\.0(?![0-9.])", version["output"]), "actual version probe differs")
        decision, = case["policyDecisions"]
        require(decision["allowed"] is True and receipt["providerId"] == decision["providerId"] == PROVIDER
                and receipt["planId"] == decision["planId"] == case["planDigest"] and receipt["taskId"] == decision["taskId"] == "cargo_outdated"
                and receipt["cwd"] == decision["cwd"] == str(execution_cwd) and receipt["command"]["args"] == decision["args"] == prefix + args
                and decision["versionArgs"] == prefix + version_args and decision["requestId"] == receipt["requestId"]
                and re.fullmatch(r"legion-audit/[0-9a-f]{64}", receipt["requestId"]) and receipt["receiptId"] == "receipt:" + receipt["requestId"]
                and decision["executable"] == receipt["command"]["executable"] == receipt["executable"]["canonicalPath"] == str(wrapper)
                and decision["expectedDigest"] == receipt["executable"]["digest"] == policy["wrapper"]["digest"] and receipt["executable"]["digestState"] == "sealed"
                and decision["acceptedExitCodes"] == [0] and decision["timeoutMs"] == 120000 and decision["stdoutLimit"] == decision["stderrLimit"] == 8388608
                and decision["environmentNames"] == receipt["environmentNames"] == receipt["command"]["environmentNames"] == sorted(environment)
                and decision["environmentDigest"] == digest(canonical(environment)) and decision["requiresNetworkSandbox"] is True
                and decision["sandbox"] == {"id": sandbox, "network": True, "filesystemScope": str(cwd)}
                and receipt["sandbox"] == {"required": True, "receiptId": sandbox, "networkEnabled": True}
                and receipt["command"]["redactedArgumentIndexes"] == receipt["command"]["redactedEnvironmentNames"] == []
                and all(receipt["processTree"][key] is True for key in ("started", "terminated", "reaped"))
                and receipt["processTree"]["hardKilled"] is False and receipt["signal"] is None, "exact SDK/process linkage differs")
        out, err = case["actualStdout"], case["actualStderr"]
        require(isinstance(out, str) and isinstance(err, str), "actual output text absent")
        for stream, data in (("stdout", out), ("stderr", err)):
            api["artifact"](receipt[stream], data)
            require(case["retainedArtifacts"][stream]["file"] == control + "/" + stream + ".log", "retained stream path differs")
            retained_item(receipts, case["retainedArtifacts"][stream], data.encode())
        if failed:
            require(result["complete"] is False and coverage["examined"] == 0 and receipt["state"] == "failed" and receipt["complete"] is False
                    and receipt["exitCode"] == 1 and receipt["gaps"] == ["failed"] and out.strip() == ""
                    and "error" in err.lower() and "Cargo.toml" in err and "[package" in err
                    and {"failed", "cargo-outdated-input-unproven:manifest-unparseable", "legacy-tool-output-unparseable:cargo_outdated", "cargo-outdated-lock-uncovered:Cargo.lock"} <= set(result["coverage_gaps"])
                    and result["details"]["findingsCount"] is None and case["rustOutdatedInput"] is None, "real operational error became clean")
            require(case["expected"] == {"complete": False, "findingCount": 0, "actualReportDependencies": None,
                    "expectedListedPin": {"name": "void", "project": "1.0.1", "latest": "1.0.2"}, "denominatorCount": 1}, "operational case expectations differ")
        else:
            report = parsed(out)
            require(set(report) == {"crate_name", "dependencies"} and report["crate_name"] == "outdated-probe" and isinstance(report["dependencies"], list), "actual package report differs")
            expected_rows = [{"name": "void", "project": "1.0.1", "compat": "---", "latest": "1.0.2", "kind": "Normal", "platform": None}] if positive else []
            require(report["dependencies"] == expected_rows and result["details"]["findingsCount"] == int(positive)
                    and receipt["state"] == "completed" and receipt["complete"] is True and receipt["gaps"] == [] and receipt["exitCode"] == 0
                    and coverage["examined"] == 1 and result["complete"] is (not uncovered), "actual raw positive/absence/partial class differs")
            require(case["expected"] == {"complete": not uncovered, "findingCount": int(positive), "actualReportDependencies": expected_rows,
                    "expectedListedPin": {"name": "void", "project": "1.0.1" if positive else "1.0.2", "latest": "1.0.2"}, "denominatorCount": len(selected)}, "fixed fixture expectations differ")
            binding = {"cwd": str(cwd), "manifest": {"path": "Cargo.toml", "digest": hashes["Cargo.toml"], "name": "outdated-probe"}, "lock": {"path": "Cargo.lock", "digest": hashes["Cargo.lock"]}, "denominatorDigest": denominator, "analysisScope": "executed-root-package-direct-dependencies"}
            require(case["rustOutdatedInput"] == result["details"]["rustOutdatedInput"] == binding, "executed root/lock binding differs")
            require(result["coverage_gaps"] == (["cargo-outdated-lock-uncovered:extra/Cargo.lock"] if uncovered else [])
                    and (uncovered or (result["status"] in ("ok", "complete") and result["degradation"] == [])), "uncovered lock silently credited")
            if positive:
                rule, anchor = "legacy.cargo_outdated.cargo-outdated", "Cargo.lock"
                identifier = digest(f"{rule}\0{anchor}\0{1}".encode())
                require(result["findings"] == [{"id": identifier, "severity": "low"}]
                        and result["details"]["findingEvidence"] == {identifier: {"ruleId": rule, "path": anchor, "line": 1, "message": "cargo_outdated reported 1 finding(s)"}}
                        and result["details"]["findingLocations"] == {identifier: [anchor]}, "valid aggregate finding not bound to executed lock")
        require(case["locatorPrecision"] == "aggregate report; package identities use actual JSON rows; Cargo.lock line 1 is fallback anchor", "case matching claim differs")
        identities.append((identity, policy["wrapper"]))
    require(bound["fixtureSources"] == all_fixtures and bound["fixtureSourcesDigest"] == digest(canonical(all_fixtures)), "whole staged fixture binding differs")
    require(len({canonical(value) for value in identities}) == 1 and row["metrics"] == {"cases": 5, "matched": 5, "mismatched": 0}, "tool/runtime changed or fixed controls incomplete")
    children = row["retainedChildProcess"]
    require(len(children) == 2, "actual child process evidence absent")
    original_cases = []
    for child, name in zip(children, ("child", "missing-tool-child")):
        require(child["schema"] == "legion-rust-outdated-child-execution/1" and child["productionQualification"] is False
                and child["status"]["success"] is True and child["status"]["exitCode"] == 0 and child["status"]["signal"] is None, "fixture child failed")
        for stream in ("stdout", "stderr"):
            item = child[stream]
            require(item["file"] == name + "." + stream + ".log" and re.fullmatch(r"sha256:[0-9a-f]{64}", item["sha256"])
                    and type(item["bytes"]) is int and item["bytes"] >= 0, "child stream identity differs")
            if receipts is not None:
                raw = (receipts / item["file"]).read_bytes()
                retained_item(receipts, item, raw)
                if stream == "stdout":
                    for line in raw.decode().splitlines():
                        if "RUST_OUTDATED_CASE " in line:
                            original_cases.append(parsed(line.split("RUST_OUTDATED_CASE ", 1)[1]))
    if receipts is not None:
        require(original_cases == row["cases"], "retained actual child record bytes differ")
    return {"provider": PROVIDER, "stage": "finding", "coverageState": "complete", "qualificationDigest": row["qualificationDigest"], "metrics": row["metrics"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    row = load(args.receipts / "cargo_outdated.json")
    validated = validate_record(args.root, row, live=True, receipts=args.receipts)
    print("RUST_OUTDATED_PROVIDER_ACCURACY_SUMMARY " + canonical({"records": [validated], "modelCalls": 0}).decode())


if __name__ == "__main__":
    main()
