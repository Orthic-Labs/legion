#!/usr/bin/env python3
"""Validate fixed constructed cargo-audit SDK controls from retained native evidence."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

ID = "legacy.security.rust-advisories"
FAMILY_SCOPE = "constructed native SDK + pinned unchanged official RustSec advisory subset; aggregate unadjudicated candidate only"
DATABASE_SCOPE = "pinned unchanged official advisory subset; no population, full database, current database, freshness or admission claim"
LOCATOR = "one native aggregate candidate at Cargo.lock:1; no vulnerability/source diagnostic localization claim"
FIXTURES = "engine/crates/legion-audit/tests/fixtures/cargo-audit"
HARNESS = "engine/crates/legion-audit/tests/cargo_audit_accuracy.rs"
POLICY = "legion-cargo-audit-offline-fixture-v1"
CONTROLS = ["positive", "absence", "missing-database", "malformed-lock", "unsupported-argv"]
PINS = {"sha256:33fbe81adca1b794f4ffe98574d59b0ebe6fcfdb310976fafed98a094c795111", "sha256:1a63bb3ab4f99a0220a8e4d8a677692afe5901cb44a949b2473c545a02028326"}
ADVISORY_DIGEST = "sha256:678bd66f3703ac7279a9b9fe4219fbe3903395d8411d899647ee8136d19241c5"
SOURCE_ROOTS = ["engine/crates/legion-audit/src", "engine/crates/legion-effects/src", "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src", "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls", FIXTURES]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HARNESS] + [f"engine/crates/{crate}/Cargo.toml" for crate in ["legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules"]]


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON key")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def absolute(value):
    require(isinstance(value, str), "missing absolute path")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts, "noncanonical retained path")
    return path


def source_file(root, relative):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and str(path) == relative and ".." not in path.parts and "\\" not in relative, "unsafe source path")
    current = root
    for part in path.parts:
        current /= part
        require(not current.is_symlink(), "source symlink refused")
    require(current.is_file(), f"missing checked-in source: {relative}")
    return current


def live_file(path, expected):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.read_bytes() == expected, f"live bytes differ: {path}")


def source_inventory(root):
    sources = {}
    for relative in SOURCE_ROOTS:
        directory = root / relative
        require(directory.is_dir() and not directory.is_symlink(), "source closure root missing/symlink")
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "source closure symlink")
            if path.is_file():
                sources[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    for relative in SOURCE_FILES:
        sources[relative] = digest(source_file(root, relative).read_bytes())
    return sources


def validate_record(repository_root, row, live=False):
    root = Path(repository_root).resolve()
    require(type(live) is bool and row["schema"] == "legion-cargo-audit-sdk-accuracy/1" and row["provider"] == ID
            and row["stage"] == "candidate" and row["scope"] == FAMILY_SCOPE and row["databaseScope"] == DATABASE_SCOPE
            and row["locatorPrecision"] == LOCATOR, "fixed provider/scope differs")
    require(all(row[key] is False for key in ("productionQualification", "selfProducerQualification", "publicHelperQualification"))
            and row["qualificationEligible"] is True and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "constructed scope/status differs")
    require(row["qualificationDigest"] == digest(encoded({key: value for key, value in row.items() if key != "qualificationDigest"})), "canonical qualification digest differs")
    bound = row["binding"]
    original_repo, retained = absolute(bound["repositoryRoot"]), absolute(bound["retainedRoot"])
    require(retained.name == "cargo-audit" and retained.parent.name == "legion-provider-qualification", "retained root differs")
    if live:
        require(str(original_repo) == str(root), "qualifying checkout differs")
    sources = source_inventory(root)
    same(bound["sources"], sources, "source/manifest/fixture closure stale or incomplete")
    require(bound["sourcesDigest"] == digest(encoded(sources)) and bound["fixture"] == HARNESS, "source closure digest/harness differs")
    specs = parsed(source_file(root, "src/registry/providers.json").read_bytes())["providers"]
    matches = [spec for spec in specs if spec["id"] == ID]
    require(len(matches) == 1, "missing/duplicate provider specification")
    spec = {key: value for key, value in matches[0].items() if key != "benchmark"}
    same(bound["providerSpec"], spec, "sanitized provider specification differs")
    require(bound["providerSpecDigest"] == digest(encoded(spec)), "canonical spec digest differs")
    tool = row["tool"]
    require(tool["version"] == "0.22.2" and tool["digest"] in PINS
            and tool["source"] == "https://github.com/rustsec/rustsec/releases/tag/cargo-audit/v0.22.2", "official native tool pin differs")
    advisory = source_file(root, FIXTURES + "/RUSTSEC-2019-0009.md").read_bytes()
    require(digest(advisory) == ADVISORY_DIGEST, "official advisory changed")
    require([case["control"] for case in row["cases"]] == CONTROLS, "fixed controls missing/duplicated/reordered")
    identities, corpus = [], {}
    for case in row["cases"]:
        control = case["control"]
        positive, failed, unsupported = control == "positive", control not in ("positive", "absence"), control == "unsupported-argv"
        cwd, run, database = retained / control / "source", retained / control / "run", retained / control / "database"
        require(case["root"] == str(cwd) and case["run"] == str(run) and case["database"] == str(database)
                and case["matched"] is True and case["invocationScope"] == ("deliberate old-argv SDK regression control" if unsupported else "shipped provider argv"), "original fixture identity differs")
        lock_control = "positive" if positive else "malformed-lock" if control == "malformed-lock" else "absence"
        require(case["fixtureLockControl"] == lock_control, "lock control differs")
        config = source_file(root, FIXTURES + "/audit.toml.in").read_text().replace("@DATABASE@", json.dumps(str(database), ensure_ascii=False))
        contents = {".cargo/audit.toml": config.encode(), "Cargo.toml": source_file(root, FIXTURES + "/Cargo.toml").read_bytes(),
                    "Cargo.lock": source_file(root, FIXTURES + "/" + lock_control + "/Cargo.lock").read_bytes()}
        fixture_sources = {path: digest(data) for path, data in contents.items()}
        same(case["fixtureSources"], fixture_sources, "checked-in fixture bytes differ")
        corpus.update({control + "/" + path: value for path, value in fixture_sources.items()})
        expected_db = {} if control == "missing-database" else {"crates/smallvec/RUSTSEC-2019-0009.md": ADVISORY_DIGEST}
        same(case["databaseSources"], expected_db, "actual local subset/missing database differs")
        if live:
            for path, data in contents.items():
                live_file(cwd / path, data)
            db = Path(database)
            require(not db.is_symlink() and not (db / ".git").exists(), "no fabricated Git metadata permitted")
            if control == "missing-database":
                require(not db.exists(), "missing DB control exists")
            else:
                files = {}
                for path in db.rglob("*"):
                    require(not path.is_symlink(), "database symlink")
                    if path.is_file():
                        files[path.relative_to(db).as_posix()] = digest(path.read_bytes())
                same(files, expected_db, "live database has extra/changed advisory content")
                live_file(database / "crates/smallvec/RUSTSEC-2019-0009.md", advisory)
        inventory, plan = case["inventory"], case["frozenPlan"]
        entries = [{"path": path, "symbols": [], "dependencies": [], "packageScripts": [], "sourceFile": False, "digest": fixture_sources[path]} for path in sorted(contents)]
        same(inventory["entries"], entries, "frozen complete fixture inventory differs")
        require(inventory["schemaVersion"] == 1 and inventory["repositoryId"] == control and inventory["generation"] == "filesystem:" + digest(encoded(entries))
                and inventory["digest"] == digest(encoded([1, control, inventory["generation"], entries])), "inventory seal differs")
        require(plan["repositoryId"] == control and plan["inventoryDigest"] == inventory["digest"] and plan["inventoryGeneration"] == inventory["generation"]
                and case["planDigest"] == digest(encoded(plan)) and case["planSignature"] == "hmac-sha256:" + hmac.new(b"constructed-cargo-audit-fixture-key", encoded(plan), hashlib.sha256).hexdigest(), "frozen plan seal differs")
        require(len(plan["providers"]) == 1 and plan["providers"][0]["id"] == ID and plan["providers"][0]["version"] == spec["providerVersion"], "frozen provider differs")
        same(case["frozenProvider"], plan["providers"][0], "retained frozen provider differs")
        cfg = plan["providers"][0]["configuration"]
        same(cfg["selector"], spec["selector"], "frozen selector differs")
        selected = [entry for entry in entries if entry["path"] == "Cargo.lock"]
        denominator = digest(encoded([inventory["digest"], cfg["selector"], selected]))
        require(cfg["denominatorCount"] == 1 and cfg["denominatorDigest"] == denominator, "complete Cargo.lock denominator differs")
        policy, receipt, result = case["policyDefinition"], case["actualSdkReceipt"], case["nativeResult"]
        native, wrapper = absolute(policy["tool"]["path"]), absolute(policy["wrapper"]["path"])
        require(not native.is_relative_to(retained) and wrapper == PurePosixPath("/usr/bin/sandbox-exec") and policy["tool"]["digest"] == tool["digest"]
                and re.fullmatch(r"sha256:[0-9a-f]{64}", policy["wrapper"]["digest"]), "native tool/wrapper identity differs")
        escaped = str(cwd).replace("\\", "\\\\").replace('"', '\\"')
        text = f'(version 1)\n(allow default)\n(allow network*)\n(allow file-read* (subpath "{escaped}"))\n(deny file-write* (subpath "{escaped}"))\n'
        profile_digest = digest(text.encode())
        profile = run / "sandbox" / ("audit-" + profile_digest.removeprefix("sha256:") + ".sb")
        sandbox_id = "sandbox:macos:" + profile_digest.removeprefix("sha256:")
        same(policy["profile"], {"path": str(profile), "text": text, "digest": profile_digest, "receiptId": sandbox_id}, "actual native profile differs")
        if live:
            live_file(profile, text.encode())
            for path, expected in [(native, tool["digest"]), (wrapper, policy["wrapper"]["digest"])]:
                actual = Path(path)
                require(actual.is_file() and not actual.is_symlink() and str(actual.resolve()) == str(path)
                        and digest(actual.read_bytes()) == expected and not actual.read_bytes().startswith(b"#!"), "live native bytes differ")
        args = ["--json"] if unsupported else ["audit", "--json"]
        prefix = ["-f", str(profile), "--", str(native)]
        env = policy["environment"]
        require(isinstance(env["PATH"], str) and env["PATH"] and env["PATH"].split(":")[0] == str(native.parent), "pinned tool PATH differs")
        for path in env["PATH"].split(":"):
            absolute(path)
        base_names = ["PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"]
        cache = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target", "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
        expected_env = {"PATH": env["PATH"], "HOME": str(retained / "home"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1", **{name: str(run / path) for name, path in cache.items()}}
        expected_policy = {"id": POLICY, "version": 1, "provider": ID, "task": "cargo_audit", "plan": case["planDigest"], "cwd": str(cwd),
            "artifactRequestId": "legion-audit/<64 lowercase hex>; one admission only", "tool": policy["tool"], "wrapper": policy["wrapper"], "profile": policy["profile"],
            "args": args, "wrappedArgs": prefix + args, "versionArgs": prefix + ["--version"], "environment": expected_env,
            "environmentAllowlist": sorted(set(base_names + list(cache) + ["PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM"])), "timeoutMs": 120000, "stdoutLimit": 8388608, "stderrLimit": 8388608,
            "sandbox": "native-macos-allow-network-deny-project-write-cargo-audit-contract", "acceptedExitCodes": [0, 1, 2]}
        same(policy, expected_policy, "exact native policy differs")
        decisions = case["policyDecisions"]
        require(len(decisions) == 1, "missing/duplicate native admission")
        decision = decisions[0]
        require(receipt["schemaVersion"] == 1 and re.fullmatch(r"legion-audit/[0-9a-f]{64}", receipt["requestId"])
                and receipt["receiptId"] == "receipt:" + receipt["requestId"] and receipt["providerId"] == ID and receipt["planId"] == case["planDigest"]
                and receipt["taskId"] == "cargo_audit" and receipt["cwd"] == str(cwd) and receipt["policyId"] == POLICY, "SDK request identity differs")
        same(decision, {"allowed": True, "requestId": receipt["requestId"], "providerId": ID, "planId": case["planDigest"], "taskId": "cargo_audit", "executable": str(wrapper),
            "expectedDigest": policy["wrapper"]["digest"], "args": prefix + args, "versionArgs": prefix + ["--version"], "cwd": str(cwd), "environmentNames": sorted(env),
            "environmentDigest": digest(encoded(env)), "timeoutMs": 120000, "stdoutLimit": 8388608, "stderrLimit": 8388608, "acceptedExitCodes": [0, 1, 2],
            "requiresNetworkSandbox": True, "sandbox": {"id": sandbox_id, "network": True, "filesystemScope": str(cwd)}}, "native admission linkage differs")
        require(receipt["policy"]["id"] == POLICY and receipt["policy"]["version"] == 1 and receipt["policy"]["allowed"] is True
                and receipt["policy"]["digest"] == digest(encoded(policy)) and receipt["state"] == "completed" and receipt["complete"] is True and receipt["gaps"] == [], "SDK execution/policy incomplete")
        exe, command, version = receipt["executable"], receipt["command"], receipt["executable"]["version"]
        require(exe["requestedPath"] == exe["canonicalPath"] == command["executable"] == str(wrapper) and exe["digest"] == policy["wrapper"]["digest"] and exe["digestState"] == "sealed"
                and command["args"] == prefix + args and command["environmentNames"] == receipt["environmentNames"] == sorted(env)
                and command["redactedArgumentIndexes"] == command["redactedEnvironmentNames"] == [], "executed wrapper/argv/environment differs")
        require(version["args"] == prefix + ["--version"] and version["qualified"] is True and version["skippedByPolicy"] is False
                and version["exitCode"] == 0 and version["output"].strip() == "cargo-audit 0.22.2", "actual native version probe differs")
        identities.append((policy["tool"], policy["wrapper"], version["output"]))
        same(receipt["sandbox"], {"required": True, "receiptId": sandbox_id, "networkEnabled": True}, "SDK sandbox differs")
        require(all(receipt["processTree"][key] is True for key in ("started", "terminated", "reaped")) and receipt["processTree"]["hardKilled"] is False
                and receipt["signal"] is None and receipt["timing"]["completedAtMs"] >= receipt["timing"]["startedAtMs"] and receipt["timing"]["durationMs"] >= 0, "actual process lifecycle incomplete")
        same(receipt["parser"], {"attempted": False, "succeeded": False, "error": None}, "SDK parser state altered")
        expected_exit = 0 if control == "absence" else 2 if control in ("malformed-lock", "unsupported-argv") else 1
        require(receipt["exitCode"] == expected_exit, "native exit differs")
        for stream in ("stdout", "stderr"):
            item, raw = receipt[stream], case["actual" + stream.title()]
            path = PurePosixPath(item["path"])
            require(not path.is_absolute() and ".." not in path.parts and item["immutable"] is True and item["raw"] == raw
                    and item["digest"] == digest(raw.encode()) and type(item["bytes"]) is int and item["bytes"] == len(raw.encode()), "retained immutable raw stream differs")
            if live:
                live_file(run / "artifacts" / path, raw.encode())
        require(result["provider"] == ID and result["applicable"] is True and result["findings"] == [] and result["details"]["processState"] == "completed"
                and result["details"]["exitCode"] == expected_exit and result["details"]["stdoutBytes"] == len(case["actualStdout"].encode())
                and result["details"]["stderrBytes"] == len(case["actualStderr"].encode()), "native provider result linkage differs")
        projected = dict(receipt)
        projected["executable"] = dict(receipt["executable"])
        projected["executable"]["version"] = {key: value for key, value in version.items() if key != "skippedByPolicy"}
        for stream in ("stdout", "stderr"):
            projected[stream] = {key: value for key, value in receipt[stream].items() if key != "raw"}
        retained_projection = result["details"]["executionReceipt"]
        for key, value in projected.items():
            same(retained_projection[key], value, "native projection changed actual SDK receipt")
        require(retained_projection["requestArgs"] == ["--json"] and retained_projection["reportSource"] == "stdout" and retained_projection["report"] is None, "shipped report contract differs")
        coverage = result["coverage"]
        require(coverage["denominator_digest"] == denominator and coverage["expected"] == coverage["examined"] == 1, "native denominator coverage differs")
        candidates = result["details"]["candidates"]
        if failed:
            require(case["actualStdout"] == "" and case["actualStderr"] and case["actualToolReport"] is None and result["complete"] is False
                    and result["details"]["findingsCount"] is None and candidates == [] and result["coverage_gaps"] == coverage["gaps"] == ["legacy-tool-output-unparseable:cargo_audit"], "native error became clean or candidate evidence")
            marker = {"missing-database": "error loading advisory database", "malformed-lock": "Couldn't load", "unsupported-argv": "--json"}[control]
            require(marker in case["actualStderr"], "actual failure cause differs")
        else:
            raw = parsed(case["actualStdout"])
            same(case["actualToolReport"], raw, "parsed actual report differs")
            count = int(positive)
            same(raw["database"], {"advisory-count": 1, "last-commit": None, "last-updated": None}, "actual subset metadata/freshness differs")
            same(raw["lockfile"], {"dependency-count": 1}, "actual lock population differs")
            require(raw["settings"]["ignore"] == [] and raw["settings"]["target_arch"] == raw["settings"]["target_os"] == [] and raw["settings"]["severity"] is None, "actual report filtered advisories")
            vulnerabilities = raw["vulnerabilities"]
            require(type(vulnerabilities["count"]) is int and vulnerabilities["count"] == count and len(vulnerabilities["list"]) == count
                    and vulnerabilities["found"] is positive, "duplicate-aware actual vulnerability count differs")
            if positive:
                vulnerability = vulnerabilities["list"][0]
                require(vulnerability["advisory"]["id"] == "RUSTSEC-2019-0009" and vulnerability["package"]["name"] == "smallvec"
                        and vulnerability["package"]["version"] == "0.6.9", "planted advisory/package/version differs")
            require(result["complete"] is True and result["coverage_gaps"] == result["degradation"] == coverage["gaps"] == []
                    and result["details"]["findingsCount"] == count, "native positive/clean incomplete")
            rule = "legacy.cargo_audit.cargo-audit"
            expected_candidates = [{"id": digest(f"{rule}\0Cargo.lock\0{1}".encode()), "ruleId": rule, "role": "candidate-generator", "claim": "cargo_audit reported 1 finding(s)",
                "severityHint": "critical", "evidence": [{"file": "Cargo.lock", "line": 1}], "evidenceStrength": "candidate", "verdict": "UNADJUDICATED", "adjudicationRequired": True}] if positive else []
            same(candidates, expected_candidates, "native aggregate candidate identity/evidence differs")
    require(all(identity == identities[0] for identity in identities), "native tool/wrapper changed between controls")
    same(bound["fixtureSources"], corpus, "full corpus binding differs")
    require(bound["fixtureSourcesDigest"] == digest(encoded(corpus)), "corpus digest differs")
    same(row["metrics"], {"cases": 5, "matched": 5, "mismatched": 0}, "fixed metrics differ")
    return {"provider": ID, "stage": "candidate", "scope": FAMILY_SCOPE, "qualificationDigest": row["qualificationDigest"],
            "productionQualification": False, "selfProducerQualification": False, "publicHelperQualification": False,
            "cases": 5, "positiveCases": 1, "cleanCases": 1, "errorCases": 3, "truePositives": 1, "falsePositives": 0, "falseNegatives": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    files = sorted(args.receipts.glob("legacy_security_*.json"))
    require([path.name for path in files] == ["legacy_security_rust-advisories.json"], "missing/duplicate provider record")
    summary = validate_record(args.root, parsed(files[0].read_bytes()), live=True)
    print("CARGO_AUDIT_PROVIDER_ACCURACY_SUMMARY " + json.dumps({"records": [summary], "modelCalls": 0}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
