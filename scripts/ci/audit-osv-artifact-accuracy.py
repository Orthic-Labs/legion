#!/usr/bin/env python3
"""Fixed constructed OSV SDK/artifact controls; never qualifies production admission."""
import argparse
import hashlib
import hmac
import io
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

ID = "dependency.osv"
FAMILY_SCOPE = "constructed native SDK + one official advisory offline cache + frozen registry artifact controls; manifest default locus only"
FIXTURES = "engine/crates/legion-audit/tests/fixtures/osv"
HARNESS = "engine/crates/legion-audit/tests/osv_accuracy.rs"
ARGV = ["scan", "source", "--offline", "--format", "json", "--all-packages", "-r", "."]
POLICY = "legion-osv-sdk-offline-artifact-fixture-v1"
PINS = {"sha256:f1e1cc84b6e365b79b874cb9028a4f74ac64666094b542f1eb196b10f44b505e", "sha256:5c2a2e2a686e34c0674e0a463aa626467df5d9fba0ed06870a2eb684dc434de3"}
ADVISORY = "GHSA-35jh-r3h4-6jhm"
ADVISORY_DIGEST = "sha256:3060fadb9a686e5041d53fe5c20c7844b2a0a49ce8d7b3d89d70703be02ec4f1"
ADVISORY_URL = "https://raw.githubusercontent.com/github/advisory-database/95c688698ee6767a611e157d7329d11f3e0a1f4b/advisories/github-reviewed/2021/05/GHSA-35jh-r3h4-6jhm/GHSA-35jh-r3h4-6jhm.json"
SOURCE_ROOTS = ["engine/crates/legion-audit/src", "engine/crates/legion-effects/src", "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src", "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls", FIXTURES]
SOURCE_FILES = ["engine/Cargo.lock", "engine/Cargo.toml", HARNESS] + [f"engine/crates/{crate}/Cargo.toml" for crate in ["legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules"]]


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value, canonical=False):
    # Original harness deliberately emits native-insertion-json. Rust integrity
    # seals (inventory, denominator, plan) instead use canonical sorted keys.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=canonical, allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def same(actual, expected, message):
    require(encoded(actual, True) == encoded(expected, True), message)


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def absolute(value):
    require(isinstance(value, str), "absolute path missing")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts, "noncanonical retained absolute path")
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


def live_bytes(path, expected):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f"live file absent: {path}")
    require(path.read_bytes() == expected, f"live file bytes differ: {path}")


def normalized_vulnerability(raw, package, version):
    return {"schemaVersion": 1, "kind": "legion-osv-vulnerability", "provider": "osv.scanner", "providerVersion": version,
            "id": raw.get("id", raw.get("ghsa_id")),
            "package": {"name": package.get("name"), "ecosystem": package.get("ecosystem"), "version": package.get("version", package.get("purl")), "purl": package.get("purl")},
            "summary": raw.get("summary"), "severity": raw.get("severity", raw.get("database_specific", {}).get("severity")),
            "references": raw.get("related", raw.get("aliases", []))[:10], "reachability": "unknown", "evidenceRefs": []}


def validate_record(repository_root, record, live=False):
    root = Path(repository_root).resolve()
    require(type(live) is bool and isinstance(record, dict), "record/interface shape differs")
    require(record.get("schema") == "legion-osv-sdk-artifact-accuracy/1" and record.get("provider") == ID
            and record.get("stage") == "finding" and record.get("outputKind") == "findings" and record.get("scope") == FAMILY_SCOPE,
            "fixed OSV fixture identity/scope differs")
    require(all(record.get(key) is False for key in ("productionQualification", "selfProducerQualification", "publicHelperQualification")), "constructed fixture cannot qualify production/public helper")
    require(record.get("qualificationEligible") is True and record.get("status") == "pass" and type(record.get("modelCalls")) is int and record["modelCalls"] == 0, "fixture controls failed/ineligible")
    without_digest = {key: value for key, value in record.items() if key != "qualificationDigest"}
    require(record.get("qualificationDigest") == digest(encoded(without_digest)), "native original qualification digest differs")
    binding = record["binding"]
    original_repo = absolute(binding["repositoryRoot"])
    retained_root = absolute(binding["retainedRoot"])
    require(retained_root.name == "osv" and retained_root.parent.name == "legion-provider-qualification", "retained qualification directory differs")
    if live:
        require(str(original_repo) == str(root), "qualifying source checkout differs")
    sources = {}
    for relative in SOURCE_ROOTS:
        directory = root / relative
        require(directory.is_dir() and not directory.is_symlink(), "source closure root absent/symlink")
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "symlink inside source closure")
            if path.is_file():
                sources[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    for relative in SOURCE_FILES:
        sources[relative] = digest(source_file(root, relative).read_bytes())
    same(binding["sources"], sources, "implementation/fixture/manifest closure stale or incomplete")
    require(binding["sourcesDigest"] == digest(encoded(dict(sorted(sources.items())))), "source closure native digest differs")
    require(binding["harnessPath"] == HARNESS and binding["argvSource"] == "engine/crates/legion-audit/src/native_providers/security/producer.rs::dependency_osv" and binding["argv"] == ARGV, "shipped argv/harness binding differs")
    producer = source_file(root, "engine/crates/legion-audit/src/native_providers/security/producer.rs").read_text()
    require(encoded(ARGV).decode() in "".join(producer.split()), "shipped clean coverage prerequisite absent")
    specs = parsed(source_file(root, "src/registry/providers.json").read_bytes())["providers"]
    matches = [item for item in specs if item["id"] == ID]
    require(len(matches) == 1, "shipped provider missing/duplicated")
    spec = {key: value for key, value in matches[0].items() if key != "benchmark"}
    same(binding["providerSpec"], spec, "sanitized provider spec differs")
    # serde_json Map::remove uses swap_remove with preserve_order. Semantic
    # equality above binds current spec; hash the retained native-order object.
    require(binding["specDigest"] == digest(encoded(binding["providerSpec"])), "native sanitized provider digest differs")
    advisory_bytes = source_file(root, FIXTURES + "/" + ADVISORY + ".json").read_bytes()
    require(digest(advisory_bytes) == ADVISORY_DIGEST, "official advisory changed")
    same(binding["advisory"], {"url": ADVISORY_URL, "path": FIXTURES + "/" + ADVISORY + ".json", "digest": ADVISORY_DIGEST, "bytes": advisory_bytes.decode()}, "official advisory binding differs")
    archive = bytes.fromhex(source_file(root, FIXTURES + "/all.zip.hex").read_text().strip())
    with zipfile.ZipFile(io.BytesIO(archive)) as database:
        require(database.namelist() == [ADVISORY + ".json"], "offline DB scope differs")
        require(database.getinfo(ADVISORY + ".json").compress_type == zipfile.ZIP_STORED and database.read(ADVISORY + ".json") == advisory_bytes, "cache is not exact unchanged official advisory")
    tool = binding["tool"]
    require(tool["version"] == "2.2.2" and tool["digest"] in PINS and tool["source"] == "https://github.com/google/osv-scanner/releases/tag/v2.2.2", "native official tool pin differs")
    cases = record["cases"]
    require([case["caseId"] for case in cases] == ["lodash-planted", "lodash-fixed"] and record["errorControl"]["caseId"] == "malformed-lockfile", "fixed positive/clean/error controls missing or duplicated")
    identities = []
    for case in [*cases, record["errorControl"]]:
        case_id = case["caseId"]
        failed, positive = case_id == "malformed-lockfile", case_id == "lodash-planted"
        package_version = "4.17.20" if positive else "4.17.21"
        require(case["stage"] == "finding" and case["controlMatched"] is True and all(case.get(key) is False for key in ("productionQualification", "selfProducerQualification", "publicHelperQualification")), "case status/scope differs")
        fixture_path = FIXTURES + "/" + case_id + "/package-lock.json"
        fixture = source_file(root, fixture_path).read_bytes()
        same(case["source"], {"path": "package-lock.json", "fixturePath": fixture_path, "bytes": fixture.decode(), "digest": digest(fixture)}, "checked-in lock control differs")
        if not failed:
            lock = parsed(fixture)
            require(lock["packages"]["node_modules/lodash"]["version"] == package_version and lock["packages"][""]["dependencies"] == {"lodash": package_version}, "lock package control differs")
        else:
            require(fixture == b"{ malformed package-lock JSON\n", "real malformed lock changed")
        policy, receipt = case["policy"], case["actualExecutionReceipt"]
        cwd, run = retained_root / case_id / "source", retained_root / case_id / "run"
        dbpath = retained_root / case_id / "database/osv-scanner/npm/all.zip"
        require(policy["root"] == str(cwd) and policy["run"] == str(run) and policy["databaseArchive"] == str(dbpath)
                and policy["databaseDigest"] == digest(archive) and policy["sourceDigest"] == digest(fixture), "original fixture/cache/policy roots differ")
        db = case["database"]
        require(db["archivePath"] == str(dbpath) and db["archiveDigest"] == digest(archive) and db["archiveBytes"] == len(archive) and db["archiveHex"] == archive.hex(), "retained actual cache differs from checked-in DB")
        native = absolute(policy["tool"]["path"])
        wrapper = absolute(policy["wrapper"]["path"])
        require(not native.is_relative_to(retained_root) and wrapper == PurePosixPath("/usr/bin/sandbox-exec")
                and policy["tool"]["digest"] == tool["digest"] and policy["tool"]["version"] == "2.2.2"
                and re.fullmatch(r"sha256:[0-9a-f]{64}", policy["wrapper"]["digest"]), "native wrapper/tool identity differs")
        escaped = str(cwd).replace("\\", "\\\\").replace('"', '\\"')
        profile_text = f'(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath "{escaped}"))\n(deny file-write* (subpath "{escaped}"))\n'
        profile_digest = digest(profile_text.encode())
        profile_path = run / "sandbox" / ("audit-" + profile_digest.removeprefix("sha256:") + ".sb")
        sandbox_id = "sandbox:macos:" + profile_digest.removeprefix("sha256:")
        same(policy["profile"], {"path": str(profile_path), "text": profile_text, "digest": profile_digest, "receiptId": sandbox_id}, "actual native profile binding differs")
        if live:
            live_bytes(cwd / "package-lock.json", fixture)
            live_bytes(dbpath, archive)
            live_bytes(profile_path, profile_text.encode())
            for path, expected in [(native, tool["digest"]), (wrapper, policy["wrapper"]["digest"])]:
                actual = Path(path)
                require(actual.is_file() and not actual.is_symlink() and actual.resolve().as_posix() == str(path) and digest(actual.read_bytes()) == expected, "live canonical executable bytes differ")
        inventory, plan = case["inventory"], case["frozenPlan"]
        entries = inventory["entries"]
        require(len(entries) == 1 and entries[0]["path"] == "package-lock.json" and entries[0]["digest"] == digest(fixture), "frozen lock inventory differs")
        require(inventory["schemaVersion"] == 1 and inventory["repositoryId"] == case_id and inventory["generation"] == "filesystem:" + digest(encoded(entries, True))
                and inventory["digest"] == digest(encoded([1, case_id, inventory["generation"], entries], True)), "inventory seal differs")
        require(plan["repositoryId"] == case_id and plan["inventoryDigest"] == inventory["digest"] and plan["inventoryGeneration"] == inventory["generation"]
                and case["planDigest"] == digest(encoded(plan, True)) and case["planSignature"] == "hmac-sha256:" + hmac.new(b"osv-sdk-artifact-fixture-key", encoded(plan, True), hashlib.sha256).hexdigest(), "frozen plan seal differs")
        planned = plan["providers"]
        require(len(planned) == 1 and planned[0]["id"] == ID and planned[0]["version"] == spec["providerVersion"], "frozen shipped provider differs")
        configuration = planned[0]["configuration"]
        denominator = inventory["digest"] if configuration["selector"].get("op") == "always" else digest(encoded([inventory["digest"], configuration["selector"], entries], True))
        require(configuration["denominatorCount"] == 1 and configuration["denominatorDigest"] == denominator, "frozen denominator differs")
        environment = policy["environment"]
        require(set(environment) in ({"HOME", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"}, {"HOME", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "PATH"})
                and environment["HOME"] == str(run / "home") and environment["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] == str(retained_root / case_id / "database"), "exact offline cache environment differs")
        require(policy["id"] == POLICY and policy["version"] == 1 and policy["provider"] == ID and policy["scope"] == "constructed-native-sdk-offline-artifact-fixture"
                and policy["planDigest"] == case["planDigest"] and policy["inventoryDigest"] == inventory["digest"] and policy["args"] == ARGV
                and policy["timeoutMs"] == 30000 and policy["outputLimit"] == 4194304, "exact scoped policy differs")
        prefix = ["-f", str(profile_path), "--", str(native)]
        decisions = case["policyDecisions"]
        require(len(decisions) == 1 and decisions[0]["allowed"] is True, "exact SDK admission missing/duplicated")
        decision = decisions[0]
        require(receipt["schemaVersion"] == 1 and receipt["requestId"] == decision["requestId"] and re.fullmatch(r"legion-audit/[0-9a-f]{64}", receipt["requestId"])
                and receipt["receiptId"] == "receipt:" + receipt["requestId"] and receipt["providerId"] == decision["providerId"] == ID
                and receipt["planId"] == decision["planId"] == case["planDigest"] and receipt["policyId"] == decision["policyId"] == POLICY
                and receipt["taskId"] == "osv-sdk-artifact" and receipt["cwd"] == str(cwd), "actual SDK request identity differs")
        require(receipt["policy"]["id"] == POLICY and receipt["policy"]["version"] == 1 and receipt["policy"]["allowed"] is True and receipt["policy"]["digest"] == digest(encoded(policy)), "actual SDK authorization differs")
        executable, command = receipt["executable"], receipt["command"]
        require(executable["requestedPath"] == executable["canonicalPath"] == command["executable"] == str(wrapper)
                and executable["digest"] == policy["wrapper"]["digest"] and executable["digestState"] == "sealed", "receipt must identify sealed native wrapper")
        require(command["args"] == decision["args"] == prefix + ARGV and command["environmentNames"] == receipt["environmentNames"] == sorted(environment)
                and command["redactedArgumentIndexes"] == command["redactedEnvironmentNames"] == [], "executed argv/environment differs")
        version = executable["version"]
        require(version["args"] == decision["versionArgs"] == prefix + ["--version"] and version["qualified"] is True and version["skippedByPolicy"] is False and version["exitCode"] == 0
                and re.search(r"(?<![0-9.])v?2\.2\.2(?![0-9A-Za-z.+_-])", version["output"]), "actual native OSV version probe differs")
        identities.append((policy["tool"], policy["wrapper"], version["output"]))
        same(receipt["sandbox"], {"required": True, "receiptId": sandbox_id, "networkEnabled": True}, "actual deny-network sandbox differs")
        require(all(receipt["processTree"][key] is True for key in ("started", "terminated", "reaped")) and receipt["processTree"]["hardKilled"] is False and receipt["signal"] is None, "actual process lifecycle incomplete")
        require(receipt["timing"]["completedAtMs"] >= receipt["timing"]["startedAtMs"] and receipt["timing"]["durationMs"] >= 0, "process timing differs")
        same(receipt["parser"], {"attempted": False, "succeeded": False, "error": None}, "must retain actual SDK parser state")
        for stream in ("stdout", "stderr"):
            artifact = receipt[stream]
            data = artifact["raw"].encode()
            relative = PurePosixPath(artifact["path"])
            require(not relative.is_absolute() and ".." not in relative.parts and artifact["immutable"] is True and artifact["bytes"] == len(data) and artifact["digest"] == digest(data), "retained actual raw stream differs")
            if live:
                live_bytes(run / "artifacts" / relative, data)
        result = case["actualProviderResult"]
        require(result["provider"] == ID and result["applicable"] is True, "native provider identity/applicability differs")
        if failed:
            require(case["controlKind"] == "real-malformed-lockfile-process-error" and case["expectedIncomplete"] is True and case["actualIncomplete"] is True and case["qualificationEligible"] is False,
                    "failure control claims differ")
            require(receipt["state"] == "failed" and receipt["complete"] is False and receipt["exitCode"] not in (None, 0, 1) and receipt["gaps"]
                    and receipt["stderr"]["raw"] and receipt["stdout"]["raw"] == "", "malformed lock did not cause actual SDK process failure")
            require(result["complete"] is False and result["findings"] == [] and result["coverage_gaps"] and "actualArtifactInput" not in case, "failed process became native clean evidence")
            continue
        require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["gaps"] == [] and receipt["exitCode"] == int(positive), "native successful controls incomplete")
        require("Loaded npm local db from " + str(dbpath) in receipt["stderr"]["raw"], "actual offline advisory cache load unproven")
        raw = parsed(receipt["stdout"]["raw"])
        same(case["actualRawOutput"], raw, "retained JSON differs from actual SDK stdout")
        require(len(raw["results"]) == 1, "raw package source count differs")
        source = raw["results"][0]
        reported = PurePosixPath(source["source"]["path"])
        relative = reported.relative_to(cwd) if reported.is_absolute() else reported
        require(relative.as_posix() == "package-lock.json", "raw package source path differs")
        require(len(source["packages"]) == 1, "raw package count differs")
        package_row = source["packages"][0]
        package = package_row["package"]
        require(package["name"] == "lodash" and package["version"] == package_version and package["ecosystem"] == "npm", "actual parsed package/version differs")
        vulnerabilities = package_row.get("vulnerabilities", [])
        require(len(vulnerabilities) == int(positive) and (not positive or vulnerabilities[0]["id"] == ADVISORY), "actual advisory positive/absence differs")
        normalized = [normalized_vulnerability(item, package, version["output"]) for item in vulnerabilities]
        inventory_binding = {"repositoryRevision": inventory["generation"], "digest": inventory["digest"]}
        observed = dict(receipt)
        observed["tool"] = {"name": "osv-scanner", "version": version["output"], "executableDigest": tool["digest"]}
        wanted_input = {"plan": {"binding": inventory_binding, "denominator": {"pathCount": 1}}, "projection": {"files": [{"path": "package-lock.json"}]},
            "artifacts": {"dependencyReceipts": [{"manifest": "package-lock.json", "binding": inventory_binding, "executionReceipt": observed,
                "database": {"digest": digest(archive), "version": "fixture-one-official-advisory:" + ADVISORY_DIGEST, "status": "offline"},
                "paths": [{"package": "lodash@" + package_version, "reachability": "reachable", "basis": "dependency-graph"}], "findings": normalized}]}}
        same(case["actualArtifactInput"], wanted_input, "observed native artifact is not derived from actual packages/SDK receipt")
        require(case["providerConfiguration"] == configuration and result["complete"] is True and result["coverage_gaps"] == result["degradation"] == [], "native measured result incomplete")
        coverage = result["coverage"]
        require(coverage["expected"] == coverage["examined"] == 1 and coverage["denominator_digest"] == denominator and coverage["gaps"] == [], "native complete manifest denominator differs")
        analysis = result["details"]["analysis"]
        wanted_findings = [dict(item, manifest="package-lock.json") for item in normalized]
        same(analysis, {"status": "pass", "complete": True, "denominator": {"kind": "dependency-manifests", "expected": 1, "examined": 1}, "findings": wanted_findings, "coverageGaps": []}, "native dependency analysis differs from observed raw package findings")
        require(len(result["findings"]) == int(positive) and result["details"]["candidates"] == [], "native finding count/stage differs")
        labels = []
        for finding in result["findings"]:
            evidence = result["details"]["findingEvidence"][finding["id"]]
            require(evidence["provider"] == ID and evidence["path"] == "package-lock.json" and evidence["line"] == 1 and evidence["ruleId"] == ADVISORY, "native advisory locus differs")
            excerpt = digest(encoded(wanted_findings[0]))
            finding_id = digest(f"{ID}\0{ADVISORY}\0package-lock.json\0{1}\0{excerpt}".encode())
            same(evidence, {"provider": ID, "ruleId": ADVISORY, "path": "package-lock.json", "line": 1, "excerptDigest": excerpt, "redacted": True}, "native finding excerpt is not derived from observed advisory")
            severity = normalized[0]["severity"] if isinstance(normalized[0]["severity"], str) else "warning"
            same(finding, {"id": finding_id, "severity": severity}, "native finding identity differs from raw advisory")
            labels.append(f"{evidence['ruleId']}|{evidence['path']}|{evidence['line']}")
        expected = [ADVISORY + "|package-lock.json|1"] if positive else []
        same(case["expected"], expected, "literal expected control changed")
        same(case["actual"], labels, "native labels not derived from result")
        same(labels, expected, "native positive/absence mismatched or duplicated")
        missing = case["missingContextProviderResult"]
        require(missing["provider"] == ID and missing["complete"] is False and missing["findings"] == [] and missing["coverage_gaps"], "missing artifact became native clean evidence")
    require(all(identity == identities[0] for identity in identities), "native tool/wrapper changed across controls")
    same(record["metrics"], {"truePositives": 1, "falsePositives": 0, "falseNegatives": 0, "positiveCases": 1, "cleanCases": 1, "errorCases": 1}, "duplicate-aware fixture metrics differ")
    return {"provider": ID, "stage": "finding", "qualificationDigest": record["qualificationDigest"], "scope": FAMILY_SCOPE,
            "productionQualification": False, "selfProducerQualification": False, "publicHelperQualification": False,
            "cases": 2, "errorCases": 1, "truePositives": 1, "falsePositives": 0, "falseNegatives": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    files = sorted(args.receipts.glob("*.json"))
    require([path.name for path in files] == ["dependency_osv_sdk_artifact.json"], "receipt envelope missing/duplicated")
    summary = validate_record(args.root, parsed(files[0].read_bytes()), live=True)
    print("OSV_SDK_ARTIFACT_ACCURACY_SUMMARY " + json.dumps({"records": [summary], "modelCalls": 0}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
