#!/usr/bin/env python3
"""Validate constructed cargo-deny SDK controls; never production admission or full RustSec coverage."""
import argparse
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

ID = "legacy.security.rust-policy"
HARNESS = "engine/crates/legion-audit/tests/cargo_deny_accuracy.rs"
FIXTURES = "engine/crates/legion-audit/tests/fixtures/cargo-deny"
FAMILY_SCOPE = "constructed native SDK; local path dependency ban positive/absence + missing official-advisory-subset database error; all four checks executed, no advisory-detection claim"
POLICY = "legion-cargo-deny-offline-fixture-v1"
ARGV = ["--format", "json", "--offline", "check"]
PINS = {"sha256:5f65c07c459c9514f0c97cc2e2fb6b120daef2d95aee31062cab4816cf027eb1", "sha256:325ae013000059dfa398557f7bc35659e1d73af6b0c39955dff633de164f9c1e"}
ADVISORY = "sha256:89cc90b1a89167c07aa2461ae037595652e177f7ee338269de93f0dcfcd5a22d"
COMMIT = "999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b"
SOURCE_ROOTS = [f"engine/crates/{crate}/src" for crate in ["legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules"]] + ["src/registry/rules", "src/registry/controls", FIXTURES]
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
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def source_file(root, relative):
    parts = PurePosixPath(relative)
    require(not parts.is_absolute() and ".." not in parts.parts and "\\" not in relative, "unsafe source path")
    path = root
    for part in parts.parts:
        path /= part
        require(not path.is_symlink(), "source symlink refused")
    require(path.is_file(), f"source missing: {relative}")
    return path


def generated_session_provenance(relative):
    # Generated host evidence only; all other source-root files remain bound.
    return re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", relative) is not None


def sources(root):
    files = {}
    for relative in SOURCE_ROOTS:
        path = root / relative
        require(path.is_dir() and not path.is_symlink(), "source closure root missing")
        for item in path.rglob("*"):
            require(not item.is_symlink(), "source closure symlink")
            if item.is_file() and not generated_session_provenance(item.relative_to(root).as_posix()):
                files[item.relative_to(root).as_posix()] = digest(item.read_bytes())
    for relative in SOURCE_FILES:
        files[relative] = digest(source_file(root, relative).read_bytes())
    return files


def absolute(value):
    require(isinstance(value, str), "absolute path missing")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts, "noncanonical retained path")
    return path


def completion(rows):
    require(rows and rows[-1].get("type") == "summary", "terminal summary absent")
    require(sum(row.get("type") == "summary" for row in rows) == 1, "summary duplicated")
    fields = rows[-1]["fields"]
    require(set(fields) == {"advisories", "bans", "licenses", "sources"}, "all four checks not proven")
    totals, exit_code = {"errors": 0, "warnings": 0}, 0
    for bit, check in enumerate(["advisories", "bans", "licenses", "sources"]):
        stats = fields[check]
        require(set(stats) == {"errors", "warnings", "notes", "helps"} and all(type(n) is int and 0 <= n <= 4294967295 for n in stats.values()), "invalid summary statistics")
        for key in totals:
            totals[key] += stats[key]
        if stats["errors"]:
            exit_code |= 1 << bit
    observed = {"errors": 0, "warnings": 0}
    for row in rows[:-1]:
        if row.get("type") == "diagnostic":
            fields = row["fields"]
            require(isinstance(fields.get("message"), str), "malformed diagnostic")
            level = fields.get("severity")
            require(level in ("error", "warning", "note", "help"), "invalid diagnostic severity")
            if level in ("error", "warning"):
                observed[level + "s"] += 1
        else:
            require(row.get("type") == "log" and row["fields"].get("level") in ("WARN", "INFO", "DEBUG", "TRACE"), "operational error or unrecognized output")
    same(observed, totals, "diagnostics do not reconcile with summary")
    return totals["errors"] + totals["warnings"], exit_code


def validate_record(repository_root, row, live=False):
    root = Path(repository_root).resolve()
    require(row.get("schema") == "legion-cargo-deny-sdk-accuracy/1" and row.get("provider") == ID and row.get("stage") == "candidate" and row.get("scope") == FAMILY_SCOPE, "constructed fixture identity/scope differs")
    require(row.get("productionQualification") is False and row.get("qualificationEligible") is True and row.get("status") == "pass" and type(row.get("modelCalls")) is int and row["modelCalls"] == 0, "constructed controls incomplete/ineligible")
    require(row.get("databaseScope") == "official-advisory-subset fixture; no full/current RustSec database or advisory-detection claim" and row.get("admissionScope") == "explicit constructed SDK authorizer; no production CLI owner-admission claim", "qualification scope expanded")
    require(row["qualificationDigest"] == digest(encoded({key: value for key, value in row.items() if key != "qualificationDigest"})), "original qualification digest differs")
    bound = row["binding"]
    spec = next(item for item in parsed(source_file(root, "src/registry/providers.json").read_bytes())["providers"] if item["id"] == ID)
    spec = {key: value for key, value in spec.items() if key != "benchmark"}
    same(bound["providerSpec"], spec, "shipped provider differs")
    require(bound["providerSpecDigest"] == digest(encoded(spec)) and bound["fixture"] == HARNESS, "provider/harness binding differs")
    expected_sources = sources(root)
    same(bound["sources"], expected_sources, "source closure stale/incomplete")
    require(bound["sourcesDigest"] == digest(encoded(expected_sources)), "source closure digest differs")
    registry_source = source_file(root, "engine/crates/legion-audit/src/native_providers/legacy_checks/registry.rs").read_text()
    require('args:&["--format","json","--offline","check"]' in "".join(registry_source.split()), "shipped offline argv absent")
    advisory = source_file(root, FIXTURES + "/RUSTSEC-2021-0145.md").read_bytes()
    require(digest(advisory) == ADVISORY, "unchanged official advisory bytes differ")
    same(row["advisory"], {"commit": COMMIT, "path": FIXTURES + "/RUSTSEC-2021-0145.md", "digest": ADVISORY}, "official advisory source differs")
    require(row["tool"]["version"] == "0.20.2" and row["tool"]["digest"] in PINS and row["tool"]["source"] == "https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.20.2", "official native cargo-deny pin differs")
    require([case["control"] for case in row["cases"]] == ["positive", "absence", "missing-database"], "controls absent/duplicated/reordered")
    fixture_hashes, identities = {}, []
    for case in row["cases"]:
        control = case["control"]
        positive, failed = control == "positive", control == "missing-database"
        require(case["provider"] == ID and case["matched"] is True, "case identity/match differs")
        cwd, run, database = map(absolute, [case["root"], case["run"], case["database"]])
        retained = cwd.parent.parent
        require(cwd == retained / control / "source" and run == retained / control / "run" and database == retained / control / "database" and retained.name == "cargo-deny" and retained.parent.name == "legion-provider-qualification", "retained roots differ")
        template = "positive.toml" if positive else "absence.toml"
        require(case["configTemplate"] == template, "policy control template differs")
        files = {path.relative_to(root / FIXTURES / "source").as_posix(): path.read_bytes() for path in (root / FIXTURES / "source").rglob("*") if path.is_file()}
        files["deny.toml"] = source_file(root, FIXTURES + "/" + template).read_text().replace("@DATABASE@", json.dumps(str(database), ensure_ascii=False, separators=(",", ":"))).encode()
        hashes = {path: digest(data) for path, data in files.items()}
        same(case["fixtureSources"], hashes, "exact local dependency/config fixture differs")
        fixture_hashes.update({control + "/" + path: value for path, value in hashes.items()})
        inv, plan, provider = case["inventory"], case["frozenPlan"], case["frozenProvider"]
        entries = [{"path": path, "symbols": [], "dependencies": ["legion-policy-dep"] if path == "Cargo.toml" else [], "packageScripts": [], "sourceFile": path.endswith(".rs"), "digest": hashes[path]} for path in sorted(files)]
        same(inv["entries"], entries, "frozen fixture inventory differs")
        require(inv["schemaVersion"] == 1 and inv["repositoryId"] == control and inv["generation"] == "filesystem:" + digest(encoded(entries)) and inv["digest"] == digest(encoded([1, control, inv["generation"], entries])), "inventory seal differs")
        require(plan["repositoryId"] == control and plan["inventoryDigest"] == inv["digest"] and plan["inventoryGeneration"] == inv["generation"] and case["planDigest"] == digest(encoded(plan)) and case["planSignature"] == "hmac-sha256:" + hmac.new(b"constructed-cargo-deny-fixture-key", encoded(plan), hashlib.sha256).hexdigest(), "frozen plan seal differs")
        same(plan["providers"], [provider], "shipped frozen provider differs")
        selected = [entry for entry in entries if entry["path"].endswith("Cargo.toml") or entry["path"].endswith(".rs")]
        denominator = digest(encoded([inv["digest"], spec["selector"], selected]))
        require(provider["id"] == ID and provider["version"] == spec["providerVersion"] and provider["configuration"]["denominatorCount"] == len(selected) and provider["configuration"]["denominatorDigest"] == denominator, "frozen denominator differs")
        policy, receipt, result = case["policyDefinition"], case["actualSdkReceipt"], case["nativeResult"]
        tool, wrapper = absolute(policy["tool"]["path"]), absolute(policy["wrapper"]["path"])
        require(tool.name == "cargo-deny" and not tool.is_relative_to(retained) and policy["tool"]["digest"] == row["tool"]["digest"] and wrapper == PurePosixPath("/usr/bin/sandbox-exec"), "native executable identity differs")
        escaped = str(cwd).replace("\\", "\\\\").replace('"', '\\"')
        text = f'(version 1)\n(allow default)\n(allow network*)\n(allow file-read* (subpath "{escaped}"))\n(deny file-write* (subpath "{escaped}"))\n'
        profile_digest = digest(text.encode())
        profile = run / "sandbox" / ("audit-" + profile_digest[7:] + ".sb")
        sandbox = "sandbox:macos:" + profile_digest[7:]
        same(policy["profile"], {"path": str(profile), "text": text, "digest": profile_digest, "receiptId": sandbox}, "shipped native sandbox binding differs")
        prefix = ["-f", str(profile), "--", str(tool)]
        require(policy["id"] == POLICY and policy["version"] == 1 and policy["provider"] == ID and policy["task"] == "cargo_deny" and policy["plan"] == case["planDigest"] and policy["cwd"] == str(cwd) and policy["args"] == ARGV and policy["wrappedArgs"] == prefix + ARGV and policy["versionArgs"] == prefix + ["--version"] and policy["acceptedExitCodes"] == list(range(16)) and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 8388608 and policy["sandbox"] == "native-macos-allow-network-deny-project-write-cargo-deny-contract", "exact constructed admission differs")
        cache = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target", "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
        env = {"PATH": policy["environment"]["PATH"], "HOME": str(retained / "home"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1", **{name: str(run / path) for name, path in cache.items()}}
        same(policy["environment"], env, "isolated production environment differs")
        metadata_toolchain = case["metadataToolchain"]
        metadata_bin = absolute(metadata_toolchain["bin"])
        require(env["PATH"].split(":")[:2] == [str(tool.parent), str(metadata_bin)] and metadata_toolchain["cargoVersion"].startswith("cargo 1.98.0 ") and metadata_toolchain["rustcVersion"].startswith("rustc 1.98.0 ") and all(re.fullmatch(r"sha256:[0-9a-f]{64}", metadata_toolchain[key]) for key in ("cargoDigest", "rustcDigest")), "actual pinned metadata toolchain differs")
        if live:
            for name in ("cargo", "rustc"):
                require(digest((Path(metadata_bin) / name).read_bytes()) == metadata_toolchain[name + "Digest"], "live metadata toolchain changed")
        same(policy["environmentAllowlist"], sorted({"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM", *cache}), "production environment allowlist differs")
        require(receipt["schemaVersion"] == 1 and re.fullmatch(r"legion-audit/[0-9a-f]{64}", receipt["requestId"]) and receipt["receiptId"] == "receipt:" + receipt["requestId"] and receipt["providerId"] == ID and receipt["planId"] == case["planDigest"] and receipt["taskId"] == "cargo_deny" and receipt["cwd"] == str(cwd) and receipt["policyId"] == receipt["policy"]["id"] == POLICY and receipt["policy"]["allowed"] is True and receipt["policy"]["digest"] == digest(encoded(policy)), "actual SDK receipt linkage differs")
        same(receipt["command"]["args"], prefix + ARGV, "actual shipped argv differs")
        require(receipt["command"]["executable"] == receipt["executable"]["canonicalPath"] == str(wrapper) and receipt["executable"]["digest"] == policy["wrapper"]["digest"], "actual SDK executable differs")
        version = receipt["executable"]["version"]
        require(version["args"] == prefix + ["--version"] and version["output"].strip() == "cargo-deny 0.20.2" and version["qualified"] is True and version["exitCode"] == 0 and version["skippedByPolicy"] is False, "actual version probe differs")
        require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["exitCode"] == (2 if positive else 1 if failed else 0) and receipt["signal"] is None and receipt["gaps"] == [] and all(receipt["processTree"][key] is True for key in ("started", "terminated", "reaped")), "actual SDK process completion differs")
        same(receipt["sandbox"], {"required": True, "receiptId": sandbox, "networkEnabled": True}, "native sandbox proof differs")
        require(len(case["policyDecisions"]) == 1 and case["policyDecisions"][0]["allowed"] is True and case["policyDecisions"][0]["requestId"] == receipt["requestId"] and case["policyDecisions"][0]["args"] == prefix + ARGV and case["policyDecisions"][0]["acceptedExitCodes"] == list(range(16)), "exact real SDK admission absent")
        decision = case["policyDecisions"][0]
        require(decision["providerId"] == ID and decision["planId"] == case["planDigest"] and decision["taskId"] == "cargo_deny" and decision["cwd"] == str(cwd) and decision["expectedDigest"] == policy["wrapper"]["digest"] and decision["versionArgs"] == prefix + ["--version"] and decision["environmentDigest"] == digest(encoded(env)) and decision["environmentNames"] == sorted(env) and decision["timeoutMs"] == 120000 and decision["stdoutLimit"] == decision["stderrLimit"] == 8388608 and decision["requiresNetworkSandbox"] is True, "real scoped request differs")
        require(receipt["environmentNames"] == sorted(env) and receipt["command"]["environmentNames"] == sorted(env) and receipt["command"]["redactedArgumentIndexes"] == [] and receipt["command"]["redactedEnvironmentNames"] == [], "actual environment/redaction proof differs")
        projected = result["details"]["executionReceipt"]
        for key in ("receiptId", "requestId", "providerId", "planId", "policyId", "policy", "taskId", "state", "complete", "command", "cwd", "environmentNames", "sandbox", "processTree", "timing", "exitCode", "signal", "gaps"):
            same(projected[key], receipt[key], "native producer receipt projection differs: " + key)
        for stream in ("stdout", "stderr"):
            item, raw = receipt[stream], case["actual" + stream.capitalize()]
            relative = PurePosixPath(item["path"])
            require(not relative.is_absolute() and ".." not in relative.parts and str(relative).startswith(receipt["requestId"] + "/"), "unsafe actual SDK artifact path")
            require(item["raw"] == raw and item["immutable"] is True and item["digest"] == digest(raw.encode()) and item["bytes"] == len(raw.encode()), "actual raw SDK artifact differs")
            same({k: v for k, v in item.items() if k != "raw"}, projected[stream], "producer artifact reference differs")
            if live:
                require((Path(run) / "artifacts" / item["path"]).read_bytes() == raw.encode(), "retained immutable SDK artifact changed")
        rows = [parsed(line) for line in case["actualStderr"].splitlines() if line.strip()]
        same(case["actualToolReport"], rows, "actual JSONL differs")
        require(result["provider"] == ID and result["applicable"] is True and result["findings"] == [], "native candidate provider differs")
        candidates = result["details"]["candidates"]
        if failed:
            require(result["complete"] is False and result["status"] == "partial" and "cargo-deny-completion-unproven" in result["coverage_gaps"] and result["details"]["findingsCount"] is None and candidates == [] and not any(item.get("type") == "summary" for item in rows) and any(item.get("type") == "log" and item["fields"].get("level") == "ERROR" for item in rows) and str(database / "advisory-db-3157b0e258782691") in case["actualStderr"], "operational database failure became findings/clean")
            require(case["gitSetup"] == [], "missing database control unexpectedly seeded")
        else:
            count, exit_code = completion(rows)
            require((count, exit_code) == ((1, 2) if positive else (0, 0)), "positive/clean native control differs")
            require(result["complete"] is True and result["status"] in ("ok", "complete") and result["coverage_gaps"] == [] and result["degradation"] == [] and result["details"]["findingsCount"] == count, "native all-check completion differs")
            coverage = result["coverage"]
            require(coverage["expected"] == coverage["examined"] == len(selected) and coverage["denominator_digest"] == denominator and coverage["gaps"] == [], "native coverage differs")
            expected_candidates = []
            if positive:
                rule, anchor = "legacy.cargo_deny.cargo-deny", selected[0]["path"]
                expected_candidates = [{"id": digest(f"{rule}\0{anchor}\0{1}".encode()), "ruleId": rule, "role": "candidate-generator", "claim": "cargo_deny reported 1 finding(s)", "severityHint": "high", "evidence": [{"file": anchor, "line": 1}], "evidenceStrength": "candidate", "verdict": "UNADJUDICATED", "adjudicationRequired": True}]
                require(any(item.get("type") == "diagnostic" and "explicitly banned" in item["fields"].get("message", "") for item in rows), "actual ban diagnostic absent")
            same(candidates, expected_candidates, "native aggregate candidate differs")
            setup = case["gitSetup"]
            require(len(setup) == 5 and [item["args"][0] for item in setup] == ["init", "add", "commit", "show", "ls-tree"] and all(item["exitCode"] == 0 for item in setup) and re.fullmatch(r"[0-9a-f]{40}\n[^\n]+\n", setup[3]["stdout"]) and "crates/atty/RUSTSEC-2021-0145.md" in setup[4]["stdout"], "actual Git subset setup proof absent")
            if live:
                db = Path(database) / "advisory-db-3157b0e258782691"
                require((db / "crates/atty/RUSTSEC-2021-0145.md").read_bytes() == advisory and (db / ".git/HEAD").is_file() and not (db / ".git/FETCH_HEAD").exists(), "actual unchanged fixture DB differs")
        if live:
            for path, data in files.items():
                require((Path(cwd) / path).read_bytes() == data, "audited fixture changed")
            for path, expected in [(tool, policy["tool"]["digest"]), (wrapper, policy["wrapper"]["digest"])]:
                require(Path(path).resolve().as_posix() == str(path) and digest(Path(path).read_bytes()) == expected, "live native executable changed")
            require(Path(profile).read_bytes() == text.encode(), "live profile changed")
        identities.append((policy["tool"], policy["wrapper"], version["output"], metadata_toolchain))
    require(all(identity == identities[0] for identity in identities), "native executables changed across controls")
    same(bound["fixtureSources"], fixture_hashes, "fixture corpus binding differs")
    require(bound["fixtureSourcesDigest"] == digest(encoded(fixture_hashes)), "fixture corpus digest differs")
    same(row["metrics"], {"cases": 3, "matched": 3, "mismatched": 0}, "control metrics differ")
    return {"provider": ID, "stage": "candidate", "scope": FAMILY_SCOPE, "productionQualification": False, "qualificationDigest": row["qualificationDigest"], "positiveCases": 1, "cleanCases": 1, "errorCases": 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    files = list(args.receipts.glob("legacy_security_rust-policy.json"))
    require(len(files) == 1, "exact native cargo-deny receipt missing")
    summary = validate_record(args.root, parsed(files[0].read_bytes()), live=True)
    print("CARGO_DENY_PROVIDER_ACCURACY_SUMMARY " + json.dumps({"records": [summary], "modelCalls": 0}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
