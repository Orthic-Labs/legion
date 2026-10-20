#!/usr/bin/env python3
"""Replay native Syft evidence; bounded SBOM/license qualification; target build provenance stays unproven."""
import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tarfile

ID = "supply-chain.license-sbom-provenance"
FAMILY = "supply-chain-native"
HARNESS = "engine/crates/legion-audit/src/native_providers/security/supply_chain_qualification_tests.rs"
VALIDATOR = "scripts/ci/audit-supply-chain-native-accuracy.py"
SCOPE = "native Syft dual-format SBOM + explicit license policy; full constructed npm-v3 lock including dev/transitive; audited target build provenance unproven"
POLICY = "legion-supply-chain-syft-fixture-only/1"
SYFT_CONFIGURATION = "check-for-app-update: false\njavascript:\n  include-dev-dependencies: true\n  search-remote-licenses: false\nexclude: []\n"
LICENSE_POLICY = {"schema": "legion-supply-chain-license-policy/1", "allow": ["MIT", "Apache-2.0", "BSD-3-Clause"], "deny": ["GPL-3.0-only"], "unknown": "unproven"}
CONTROLS = ["nonempty-clean", "license-violation", "unknown-license", "malformed-lock", "missing-package", "malformed-receipt", "mismatched-binding", "substituted-subject", "tampered-provenance", "tool-unavailable", "admission-unavailable", "sandbox-missing", "source-drift"]
PINS = {"syft_1.55.0_darwin_arm64.tar.gz": "sha256:1217c258bd5eb91ef3189cf22a82e02f9cac07e4ce934350f428e93aff674625", "syft_1.55.0_darwin_amd64.tar.gz": "sha256:e2e5831cbabaec9a36fe65c34755c1113982c842a685edce3ce0b54a0ded8003"}
TOOL_SOURCE = "https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_checksums.txt"
ROOTS = ["engine/crates/" + name + "/src" for name in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")] + ["src/registry/rules", "src/registry/controls"]
FILES = ["src/registry/providers.json", "engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", VALIDATOR, "scripts/ci/tests/test_audit_supply_chain_native_accuracy.py", "scripts/ci/schemas/audit-supply-chain-native-accuracy.schema.json", "scripts/ci/audit-qualification-records.py", "scripts/ci/right-git-ci.sh", ".github/workflows/ci.yml"] + ["engine/crates/" + name + "/Cargo.toml" for name in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")]
AUTHORITY_GAPS = [{"kind": "supply-chain-provenance-invalid"}, {"kind": "supply-chain-provenance-authority-unavailable", "reason": "build-attestation-verification-owner-unavailable"}]

def require(value, message):
    if not value:
        raise AssertionError(message)

def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()

def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()

def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)

def parsed(data):
    def pairs(rows):
        require(len(rows) == len(dict(rows)), "duplicate JSON field")
        return dict(rows)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))

def sealed(row):
    row = copy.deepcopy(row)
    row.pop("qualificationDigest", None)
    row["qualificationDigest"] = digest(encoded(row))
    return row

def path(value):
    require(isinstance(value, str), "retained path missing")
    result = PurePosixPath(value)
    require(result.is_absolute() and ".." not in result.parts and str(result) == value, "retained path unsafe")
    return result

def regular(value):
    target = Path(value)
    require(target.is_absolute(), "absolute file missing")
    cursor = Path(target.anchor)
    for bit in target.parts[1:]:
        cursor /= bit
        require(not cursor.is_symlink(), "symlink in retained/source path")
    require(target.is_file(), "retained/source file missing: " + str(target))
    return target

def semantics(registry):
    registry = copy.deepcopy(registry)
    for provider in registry["providers"]:
        for key in ("status", "qualificationDigest", "qualification"):
            provider["benchmark"].pop(key, None)
    return registry

def sources(root):
    names = set(FILES)
    for relative in ROOTS:
        folder = root / relative
        require(folder.is_dir() and not folder.is_symlink(), "source root absent/unsafe")
        for item in folder.rglob("*"):
            require(not item.is_symlink(), "source symlink")
            name = item.relative_to(root).as_posix()
            if item.is_file() and not re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", name):
                names.add(name)
    files = {}
    for name in sorted(names):
        raw = regular(root / name).read_bytes()
        files[name] = digest(encoded(semantics(parsed(raw)))) if name == "src/registry/providers.json" else digest(raw)
    return {"files": files, "digest": digest(encoded(files)), "registryRawDigest": digest(regular(root / "src/registry/providers.json").read_bytes())}

def source_files(root):
    return sorted(sources(Path(root))["files"])

def source_digest(root, relative):
    raw = regular(Path(root) / relative).read_bytes()
    return digest(encoded(semantics(parsed(raw)))) if relative == "src/registry/providers.json" else digest(raw)

def summary(row, refusals):
    return {"family": FAMILY, "provider": ID, "status": "pass", "cases": len(CONTROLS), "tamperRefusals": refusals, "boundedSbomLicenseKnownAnswerEligible": True, "qualificationEligible": True, "targetBuildProvenanceVerified": False, "requiredGap": "supply-chain-provenance-invalid"}

def fixture_lock(license):
    return json.dumps({"lockfileVersion": 3, "requires": True, "packages": {
        "node_modules/direct": {"version": "1.0.0", "license": "MIT", "dependencies": {"transitive": "2.0.0"}},
        "node_modules/direct/node_modules/transitive": {"version": "2.0.0", "license": license},
        "node_modules/dev-only": {"version": "3.0.0", "license": "Apache-2.0", "dev": True}}}, sort_keys=False, indent=2) + "\n"

def package_identity(value):
    require(isinstance(value, str), "package URL absent")
    base = re.split(r"[?#]", value)[0]
    match = re.fullmatch(r"pkg:([^/]+)/(.+)@([^@]+)", base)
    require(match is not None, "package URL lacks exact version")
    kind, name, version = match.groups()
    name = name.replace("%40", "@").replace("%2F", "/").replace("%2f", "/")
    if kind == "pypi":
        name = name.lower().replace("_", "-").replace(".", "-")
    require(not any(char.isspace() for char in name + version), "package URL contains whitespace")
    return "pkg:" + kind + "/" + name.replace("@", "%40") + "@" + version

def lock_packages(raw):
    doc = parsed(raw)
    require(isinstance(doc.get("packages"), dict) and doc["packages"], "dependency-manifest-unparsed")
    result = set()
    for key, entry in doc["packages"].items():
        if key == "":
            continue
        require("node_modules/" in key and entry.get("link") is not True and isinstance(entry.get("version"), str), "dependency-manifest-unparsed")
        result.add(package_identity("pkg:npm/" + key.rsplit("node_modules/", 1)[1] + "@" + entry["version"]))
    require(result, "dependency-manifest-unparsed")
    return result

def sbom(format, raw):
    try:
        doc = parsed(raw)
    except (ValueError, AssertionError):
        return None, "sbom-json-invalid"
    cdx = format == "cyclonedx"
    if cdx:
        if doc.get("bomFormat") != "CycloneDX" or doc.get("specVersion") not in ("1.5", "1.6", "1.7"):
            return None, "sbom-format-invalid"
        rows = doc.get("components")
    else:
        if doc.get("spdxVersion") != "SPDX-2.3" or doc.get("SPDXID") != "SPDXRef-DOCUMENT":
            return None, "sbom-format-invalid"
        rows = doc.get("packages")
    if not isinstance(rows, list):
        return None, "sbom-components-missing" if cdx else "sbom-packages-missing"
    result = {}
    for row in rows:
        purls = [row["purl"]] if cdx and isinstance(row.get("purl"), str) else [ref["referenceLocator"] for ref in row.get("externalRefs", []) if ref.get("referenceType") == "purl" and isinstance(ref.get("referenceLocator"), str)] if not cdx else []
        if not purls:
            if (cdx and row.get("type") in ("file", "operating-system")) or (not cdx and row.get("primaryPackagePurpose") in ("FILE", "CONTAINER", "OTHER")):
                continue
            return None, "sbom-package-purl-missing"
        if len(purls) != 1:
            return None, "sbom-package-purl-ambiguous"
        try:
            key = package_identity(purls[0])
        except AssertionError:
            return None, "sbom-purl-invalid"
        licenses = set()
        if cdx:
            for license in row.get("licenses", []):
                value = license.get("expression", license.get("license", {}).get("id", license.get("license", {}).get("name")))
                if not isinstance(value, str):
                    return None, "sbom-license-invalid"
                licenses.add(value)
        else:
            value = row.get("licenseConcluded")
            if value in (None, "NOASSERTION", "NONE"):
                value = row.get("licenseDeclared")
            if isinstance(value, str):
                licenses.add(value)
        if key in result:
            return None, "sbom-package-duplicate"
        result[key] = licenses
    return (result, None) if result else (None, "sbom-package-inventory-empty")

def reconcile(packages, cdx, spdx, policy=LICENSE_POLICY):
    gaps, findings, maps = [], [], []
    for format, raw in (("cyclonedx", cdx), ("spdx", spdx)):
        found, error = sbom(format, raw)
        if error:
            gaps.append({"kind": error, "format": format})
        else:
            maps.append(found)
    allow, deny = set(policy.get("allow", [])), set(policy.get("deny", []))
    valid = policy.get("schema") == "legion-supply-chain-license-policy/1" and policy.get("unknown") == "unproven" and len(policy.get("allow", [])) == len(allow) and len(policy.get("deny", [])) == len(deny) and allow and allow.isdisjoint(deny) and not ({"", "NONE", "NOASSERTION"} & (allow | deny))
    if not valid:
        gaps.append({"kind": "supply-chain-license-policy-missing-or-invalid"})
    examined = 0
    if len(maps) == 2:
        for package in sorted(packages):
            if package not in maps[0] or package not in maps[1]:
                gaps.append({"kind": "sbom-package-missing", "name": package})
                continue
            examined += 1
            left, right = maps[0][package], maps[1][package]
            if left != right:
                gaps.append({"kind": "sbom-license-formats-disagree", "name": package})
                continue
            if not valid:
                continue
            if not left:
                gaps.append({"kind": "sbom-package-license-missing", "name": package})
            for license in sorted(left):
                if license in deny:
                    findings.append({"ruleId": "supply-chain.license-policy-denied", "package": package, "license": license, "severity": "high", "evidence": "both-native-sbom-formats", "policyDigest": digest(encoded(policy))})
                elif license not in allow:
                    gaps.append({"kind": "supply-chain-license-undecided", "name": package, "license": license})
        if set(maps[0]) != set(maps[1]):
            gaps.append({"kind": "sbom-package-formats-disagree"})
    if not packages:
        gaps.append({"kind": "dependency-inventory-missing"})
    return {"complete": not gaps, "expected": len(packages), "examined": examined, "findings": findings, "coverageGaps": gaps, "cycloneDxDigest": digest(cdx), "spdxDigest": digest(spdx), "licensePolicyDigest": digest(encoded(policy))}

def provenance(chain, binding):
    if "provenance" not in chain:
        return {"present": False, "verified": False, "reasons": ["absent", "authority-unavailable"]}
    item, reasons = chain["provenance"], []
    if item.get("binding") != binding:
        reasons.append("binding-mismatch")
    receipt = item.get("executionReceipt") or {}
    if not (receipt.get("complete") is True and receipt.get("state") == "completed" and receipt.get("exitCode") == 0 and (receipt.get("policy") or {}).get("allowed") is True and receipt.get("processTree", {}).get("reaped") is True and receipt.get("planId") == binding.get("digest")):
        reasons.append("malformed-receipt")
    try:
        statement = parsed(item.get("raw", ""))
    except (ValueError, AssertionError):
        return {"present": True, "verified": False, "reasons": reasons + ["malformed-statement", "authority-unavailable"]}
    if statement.get("_type") != "https://in-toto.io/Statement/v1" or statement.get("predicateType") != "https://slsa.dev/provenance/v1" or not isinstance(statement.get("predicate"), dict):
        reasons.append("malformed-statement")
    subject = chain.get("subjectArtifact", {})
    values = subject.get("rawBytes")
    valid = isinstance(values, list) and all(type(value) is int and 0 <= value <= 255 for value in values)
    hash_ = digest(bytes(values)) if valid else None
    if not (valid and subject.get("digest") == hash_ and chain.get("sourceBefore", {}).get("files", {}).get(subject.get("path")) == hash_ and any(row.get("name") == subject.get("path") and row.get("digest", {}).get("sha256") == hash_[7:] for row in statement.get("subject", []))):
        reasons.append("subject-mismatch")
    return {"present": True, "verified": False, "reasons": reasons + ["authority-unavailable"]}

def document_bytes(document, format, binding, config):
    raw = document.get("raw")
    if not isinstance(raw, str) or document.get("digest") != digest(raw.encode()) or config.get("raw") != SYFT_CONFIGURATION or config.get("digest") != digest(SYFT_CONFIGURATION.encode()):
        return None
    receipt = document.get("receipt", {})
    args = (receipt.get("command") or {}).get("args", [])
    suffix = args[4:] if len(args) >= 4 and args[0] == "-f" and args[2] == "--" else args
    expected = ["scan", "dir:.", "--config", config.get("path"), "--override-default-catalogers", "all", "-o", "cyclonedx-json" if format == "cyclonedx" else "spdx-json", "-q"]
    good = suffix == expected and receipt.get("providerId") == ID and receipt.get("planId") == binding.get("digest") and receipt.get("state") == "completed" and receipt.get("complete") is True and receipt.get("exitCode") == 0 and receipt.get("signal") is None and receipt.get("gaps") == [] and (receipt.get("policy") or {}).get("allowed") is True and receipt.get("sandbox", {}).get("required") is True and receipt.get("sandbox", {}).get("networkEnabled") is True and receipt.get("processTree", {}).get("started") is True and receipt.get("processTree", {}).get("reaped") is True and receipt.get("processTree", {}).get("terminated") is True and receipt.get("processTree", {}).get("hardKilled") is False and (receipt.get("stdout") or {}).get("digest") == digest(raw.encode()) and (receipt.get("stdout") or {}).get("bytes") == len(raw.encode()) and (receipt.get("stdout") or {}).get("immutable") is True and (receipt.get("executable") or {}).get("version", {}).get("qualified") is True
    return raw.encode() if good else None

def analyze(input):
    chain = input.get("artifacts", {}).get("supplyChain", {})
    gaps = copy.deepcopy(chain.get("producerGaps", []))
    before, after = chain.get("sourceBefore", {}), chain.get("sourceAfter", {})
    selected = {row["path"] for row in input.get("projection", {}).get("files", [])}
    bound = chain.get("schema") == "legion-supply-chain-native-evidence/1" and before.get("complete") is True and after.get("complete") is True and before.get("files") == after.get("files") and selected == set(before.get("files", {})) and bool(selected)
    if not bound:
        gaps.append({"kind": "supply-chain-source-binding-invalid"})
    gaps += copy.deepcopy(before.get("coverageGaps", [])) + copy.deepcopy(after.get("coverageGaps", []))
    packages, lock_paths = set(), set()
    for row in chain.get("lockfiles", []):
        name, raw = row.get("path"), row.get("raw")
        if not isinstance(name, str) or not isinstance(raw, str):
            gaps.append({"kind": "dependency-manifest-unparsed"})
            continue
        if name in lock_paths or before.get("files", {}).get(name) != row.get("digest") or row.get("digest") != digest(raw.encode()):
            gaps.append({"kind": "supply-chain-lock-binding-invalid", "path": name})
            continue
        lock_paths.add(name)
        try:
            require(name == "package-lock.json", "constructed denominator changed")
            packages |= lock_packages(raw)
        except (AssertionError, ValueError):
            gaps.append({"kind": "dependency-manifest-unparsed", "path": name, "reason": "dependency-manifest-unparsed:" + name})
    if lock_paths != {name for name in selected if name == "package-lock.json"}:
        gaps.append({"kind": "supply-chain-lock-denominator-invalid"})
    if set(chain.get("lockPackages", [])) != packages:
        gaps.append({"kind": "supply-chain-lock-inventory-invalid"})
    binding = input.get("plan", {}).get("binding", {})
    cdx = document_bytes(chain.get("documents", {}).get("cyclonedx", {}), "cyclonedx", binding, chain.get("syftConfiguration", {}))
    spdx = document_bytes(chain.get("documents", {}).get("spdx", {}), "spdx", binding, chain.get("syftConfiguration", {}))
    if cdx is None or spdx is None:
        gaps.append({"kind": "sbom-native-receipt-or-artifact-invalid"})
        cdx, spdx = b"", b""
    result = reconcile(packages, cdx, spdx, chain.get("licensePolicy") or {})
    complete = bound and not gaps and result["complete"]
    gaps += result["coverageGaps"] + AUTHORITY_GAPS
    findings = copy.deepcopy(result["findings"])
    for finding in findings:
        finding.update(file="package-lock.json", line=1, message="Explicit license policy denies " + json.dumps(finding["license"]) + " for " + json.dumps(finding["package"]))
    return {"status": "unproven", "complete": False, "denominator": {"kind": "lockfile-packages", "expected": len(packages), "examined": result["examined"]}, "findings": findings, "coverageGaps": gaps, "sbomLicenseComplete": complete, "sourceCoverage": {"validatedPaths": sorted(selected) if bound else [], "complete": bound}, "reconciliation": result, "provenance": provenance(chain, binding)}

def inventory(name, raw):
    entries = [{"path": "package-lock.json", "symbols": [], "dependencies": [], "packageScripts": [], "sourceFile": False, "digest": digest(raw.encode())}]
    generation = "filesystem:" + digest(encoded(entries))
    return {"schemaVersion": 1, "repositoryId": name, "generation": generation, "entries": entries, "digest": digest(encoded([1, name, generation, entries]))}

def validate_fixture_provider(provider, spec, inv):
    config = provider["configuration"]
    # InventoryEnvelope uses the full inventory digest for the always selector.
    require(provider["id"] == ID and provider["version"] == spec["providerVersion"] and provider["cleanClaim"] == "evidence-only" and provider["benchmarkRequiredForCleanClaim"] is False and config["selector"] == {"op": "always"} and config["denominatorCount"] == 1 and config["denominatorDigest"] == inv["digest"] and config["supplyChainLicensePolicy"] == LICENSE_POLICY, "frozen fixture provider/denominator/policy differs")

def native_receipt(case, request, diagnostic, toolchain, live):
    receipt = diagnostic["record"]["receipt"]
    data = diagnostic["record"]
    same(data["schema"], "legion-native-scanner-diagnostic/1", "diagnostic schema differs")
    same(data["provider"], ID, "diagnostic provider differs")
    same(data["inventoryDigest"], case["inventory"]["digest"], "diagnostic frozen inventory differs")
    require(isinstance(diagnostic["rawBytes"], list) and all(type(value) is int and 0 <= value <= 255 for value in diagnostic["rawBytes"]), "retained diagnostic original bytes absent")
    diagnostic_raw = bytes(diagnostic["rawBytes"])
    require(diagnostic["digest"] == digest(diagnostic_raw), "retained native diagnostic digest differs")
    same(parsed(diagnostic_raw), data, "retained diagnostic bytes differ from original SDK projection")
    target = path(diagnostic["path"])
    require(target.parent == path(case["run"]) / "native-diagnostics" and target.name == ID + "-" + diagnostic["digest"][7:] + ".json", "retained diagnostic location differs")
    if live:
        require(regular(target).read_bytes() == diagnostic_raw, "retained original diagnostic changed")
    artifact_root = path(data["originalArtifactRoot"])
    require(artifact_root.parent == path(case["run"]) and artifact_root.name.startswith("legion-audit-security-"), "native artifact root differs")
    profile_text = '(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath "' + case["root"].replace('\\', '\\\\').replace('"', '\\"') + '"))\n(deny file-write* (subpath "' + case["root"].replace('\\', '\\\\').replace('"', '\\"') + '"))\n'
    profile_hash = digest(profile_text.encode())
    profile = str(artifact_root / "sandbox" / ("audit-" + profile_hash[7:] + ".sb"))
    same(data["sandboxProfile"], {"path": profile, "raw": profile_text, "digest": profile_hash}, "authenticated sandbox profile differs")
    config = case["input"]["artifacts"]["supplyChain"]["syftConfiguration"]
    same(config, {"path": str(artifact_root / "syft-native.yaml"), "raw": SYFT_CONFIGURATION, "digest": digest(SYFT_CONFIGURATION.encode())}, "native cataloger/dev/license configuration differs")
    args = request["args"]
    require(len(args) == 13 and args[:4] == ["-f", profile, "--", toolchain["syft"]["path"]] and args[4:11] == ["scan", "dir:.", "--config", config["path"], "--override-default-catalogers", "all", "-o"] and args[11] in ("cyclonedx-json", "spdx-json") and args[12] == "-q", "native argv differs")
    require(request["providerId"] == ID and request["planId"] == case["inventory"]["digest"] and request["policyId"] == "audit-native-owner-admission-v1" and request["taskId"] == "syft" and request["origin"] == "system" and request["shell"] is False and request["executable"] == "/usr/bin/sandbox-exec" and request["expectedDigest"] == toolchain["launcher"]["digest"] and request["cwd"] == case["root"] and request["acceptedExitCodes"] == [0] and request["timeoutMs"] == 120000 and request["stdoutLimit"] == request["stderrLimit"] == 8388608, "native constructed SDK request differs")
    require(request["skipVersionProbe"] is False and request["versionRequirement"] is None and request["versionArgs"] == args[:4] + ["--version"], "native version probe differs")
    require(request["requiresNetworkSandbox"] is True and request["sandbox"] == {"id": "sandbox:macos:" + profile_hash[7:], "network": True, "filesystemScope": case["root"]}, "authenticated native sandbox request differs")
    allowed = {"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE", "TEMP", "TMP", "NO_COLOR", "SEMGREP_SEND_METRICS", "SEMGREP_ENABLE_VERSION_CHECK", "SYFT_CHECK_FOR_APP_UPDATE"}
    require(set(request["environment"]) <= allowed and sorted(request["environment"]) == request["environmentAllowlist"], "native environment allowlist differs")
    for key, value in {"NO_COLOR": "1", "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0", "SYFT_CHECK_FOR_APP_UPDATE": "false"}.items():
        require(request["environment"].get(key) == value, "offline scanner environment differs")
    require(re.fullmatch(r"legion-audit/[0-9a-f]{64}", request["requestId"]) is not None, "native SDK artifact request namespace absent")
    require(receipt["requestId"] == request["requestId"] and receipt["receiptId"] == "receipt:" + request["requestId"] and receipt["schemaVersion"] == 1 and receipt["providerId"] == ID and receipt["planId"] == request["planId"] and receipt["taskId"] == "syft" and receipt["cwd"] == case["root"], "native SDK receipt identity differs")
    same(receipt["policy"], {"id": POLICY, "version": 1, "digest": digest(POLICY.encode()), "allowed": True, "reason": None}, "constructed policy receipt differs")
    require(receipt["policyId"] == POLICY, "SDK decision policy identity differs")
    same(receipt["command"], {"executable": request["executable"], "args": args, "environmentNames": sorted(request["environment"]), "redactedArgumentIndexes": [], "redactedEnvironmentNames": []}, "executed SDK command differs")
    same(receipt["environmentNames"], sorted(request["environment"]), "executed environment differs")
    same(receipt["sandbox"], {"required": True, "receiptId": request["sandbox"]["id"], "networkEnabled": True}, "SDK sandbox receipt differs")
    require(receipt["signal"] is None and receipt["processTree"]["started"] is True and receipt["processTree"]["terminated"] is True and receipt["processTree"]["reaped"] is True and receipt["processTree"]["hardKilled"] is False, "native process lifecycle incomplete")
    timing = receipt["timing"]
    require(all(type(timing[k]) is int and timing[k] >= 0 for k in ("startedAtMs", "completedAtMs", "durationMs")) and timing["startedAtMs"] > 0 and timing["completedAtMs"] >= timing["startedAtMs"] and timing["durationMs"] == timing["completedAtMs"] - timing["startedAtMs"], "native timing invalid")
    same(receipt["parser"], {"attempted": False, "succeeded": False, "error": None}, "SDK parser state substituted")
    executable = receipt["executable"]
    require(executable["requestedPath"] == executable["canonicalPath"] == "/usr/bin/sandbox-exec" and executable["digest"] == toolchain["launcher"]["digest"] and executable["digestState"] == "sealed", "native launcher identity differs")
    probe = executable["version"]
    require(probe["args"] == request["versionArgs"] and probe["exitCode"] == 0 and probe["qualified"] is True and probe["skippedByPolicy"] is False and re.fullmatch(r"syft 1\.55\.0\s*", probe["output"]) is not None, "genuine native Syft version absent")
    streams = {}
    for name in ("stdout", "stderr"):
        stream = data[name]
        require(isinstance(stream["rawBytes"], list) and all(type(value) is int and 0 <= value <= 255 for value in stream["rawBytes"]), "retained native stream invalid")
        raw = bytes(stream["rawBytes"])
        require(stream["digest"] == digest(raw) and stream["bytes"] == len(raw) and stream["immutable"] is True and stream["raw"] == raw.decode(), "retained native stream checksum differs")
        original = path(stream["originalAbsolutePath"])
        original_relative = PurePosixPath(stream["originalPath"])
        require(original.is_relative_to(artifact_root) and original == (original_relative if original_relative.is_absolute() else artifact_root / original_relative), "original SDK stream path differs")
        same(receipt[name], {"path": stream["originalPath"], "digest": stream["digest"], "bytes": stream["bytes"], "immutable": True}, "original SDK artifact link differs")
        streams[name] = raw
    completed = receipt["state"] == "completed" and receipt["complete"] is True and receipt["exitCode"] == 0 and receipt["gaps"] == []
    failed = receipt["state"] == "failed" and receipt["complete"] is False and type(receipt["exitCode"]) is int and receipt["exitCode"] != 0 and receipt["gaps"] == ["failed"]
    require(completed or (case["control"] == "malformed-lock" and failed), "native scanner failed outside malformed control")
    return args[11], receipt, streams["stdout"], completed

def validate_tools(toolchain, live):
    require(set(toolchain) == {"syft", "launcher", "archive"}, "native tool closure changed")
    require(toolchain["launcher"]["path"] == "/usr/bin/sandbox-exec" and path(toolchain["syft"]["path"]).name == "syft", "native executable paths differ")
    archive = path(toolchain["archive"]["path"])
    require(archive.name in PINS and toolchain["archive"]["digest"] == PINS[archive.name], "official archive pin differs")
    for item in toolchain.values():
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"]) is not None, "native closure digest absent")
        path(item["path"])
        if live:
            require(digest(regular(item["path"]).read_bytes()) == item["digest"], "installed native tool/launcher/archive changed")
    if live:
        with tarfile.open(regular(archive), "r:gz") as bundle:
            entries = [item for item in bundle.getmembers() if item.name in ("syft", "./syft")]
            require(len(entries) == 1 and entries[0].isfile(), "official native archive member absent/ambiguous")
            binary = bundle.extractfile(entries[0]).read()
        require(digest(binary) == toolchain["syft"]["digest"], "native binary differs from pinned official archive")
        require(binary[:4] == b"\xcf\xfa\xed\xfe" and struct.unpack("<I", binary[4:8])[0] == (0x100000C if "arm64" in archive.name else 0x1000007), "native binary architecture differs")

def expected_mutation(name, baseline):
    input = copy.deepcopy(baseline)
    chain = input["artifacts"]["supplyChain"]
    if name == "malformed-receipt":
        chain["documents"]["cyclonedx"]["receipt"]["complete"] = False
    elif name == "mismatched-binding":
        input["plan"]["binding"]["digest"] = digest(b"different source binding")
    elif name == "substituted-subject":
        chain["subjectArtifact"] = {"path": "package-lock.json", "digest": digest(b"substituted artifact"), "rawBytes": list(b"substituted artifact")}
        chain["provenance"] = {"binding": baseline["plan"]["binding"], "executionReceipt": baseline["artifacts"]["supplyChain"]["documents"]["cyclonedx"]["receipt"], "raw": encoded({"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1", "subject": [{"name": "package-lock.json", "digest": {"sha256": chain["sourceBefore"]["files"]["package-lock.json"][7:]}}], "predicate": {}}).decode()}
    elif name == "tampered-provenance":
        chain["provenance"] = {"binding": baseline["plan"]["binding"], "executionReceipt": None, "raw": "{ malformed unsigned control"}
    else:
        raise AssertionError("unknown consumer refusal")
    return input

def validate_record(repository_root, row, live=False):
    root = Path(repository_root).resolve()
    require(row.get("schema") == "legion-supply-chain-native-accuracy/1" and row.get("family") == FAMILY and row.get("provider") == ID and row.get("stage") == "candidate" and row.get("scope") == SCOPE, "bounded native identity/scope differs")
    require(row.get("status") == "pass" and row.get("boundedSbomLicenseKnownAnswerEligible") is True and row.get("qualificationEligible") is True and all(row.get(key) is False for key in ("wholeProviderQualification", "productionQualification", "targetBuildProvenanceVerified")) and type(row.get("modelCalls")) is int and row["modelCalls"] == 0 and row.get("requiredGap") == "supply-chain-provenance-invalid", "unproven audited-target contract changed")
    same(row, sealed(row), "original evidence seal differs")
    bound = row["binding"]
    expected_sources = sources(root)
    same(bound["sourceBefore"], bound["sourceAfter"], "source closure changed during native controls")
    for snapshot in (bound["sourceBefore"], bound["sourceAfter"]):
        same(snapshot["files"], expected_sources["files"], "source closure stale/incomplete")
        require(snapshot["digest"] == expected_sources["digest"], "source closure digest differs")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", snapshot["registryRawDigest"]) is not None, "raw registry digest absent")
        if live:
            require(snapshot["registryRawDigest"] == expected_sources["registryRawDigest"], "live registry changed")
    spec = next(item for item in semantics(parsed(regular(root / "src/registry/providers.json").read_bytes()))["providers"] if item["id"] == ID)
    same(bound["providerSpec"], spec, "original provider contract differs")
    require(bound["providerSpecDigest"] == digest(encoded(spec)) and bound["harness"] == HARNESS and spec["benchmark"]["requiredForCleanClaim"] is False and spec["cleanClaim"] == "evidence-only" and spec["selector"] == {"op": "always"}, "provider selector/denominator/clean claim changed")
    same(row["toolchainBefore"], row["toolchainAfter"], "native tool closure drifted")
    validate_tools(row["toolchainBefore"], live)
    require(row["syftVersion"] == "1.55.0", "native tool version changed")
    cases = row["cases"]
    same([case["control"] for case in cases], CONTROLS, "controls missing/duplicated/reordered")
    seen = set()
    for case, license in zip(cases[:4], ("BSD-3-Clause", "GPL-3.0-only", "AGPL-3.0-only", "MIT")):
        name = case["control"]
        require(case["kind"] == "native-source-control", "native control replaced by synthetic output")
        source, run = path(case["root"]), path(case["run"])
        require(source.name == "source" and source.parent.name == name and run == source.parent / "run", "native source/run isolation differs")
        require(not path(row["toolchainBefore"]["syft"]["path"]).is_relative_to(source.parent.parent), "native tool substituted inside fixture root")
        raw = "{ malformed lock\n" if name == "malformed-lock" else fixture_lock(license)
        inv = inventory(name, raw)
        same(case["inventory"], inv, "full frozen native fixture inventory differs")
        validate_fixture_provider(case["provider"], spec, inv)
        input = case["input"]
        same(input["plan"], {"binding": {"repositoryRevision": inv["generation"], "digest": inv["digest"]}, "repositoryBinding": {"revision": inv["generation"], "root": str(source)}, "denominator": {"pathCount": 1}}, "frozen native source plan differs")
        same(input["projection"], {"files": [{"path": "package-lock.json"}]}, "selected paths narrowed")
        chain = input["artifacts"]["supplyChain"]
        snapshot = {"complete": True, "files": {"package-lock.json": digest(raw.encode())}, "coverageGaps": []}
        same(chain["sourceBefore"], snapshot, "native source-before differs")
        same(chain["sourceAfter"], snapshot, "native source-after differs")
        same(chain["lockfiles"], [{"path": "package-lock.json", "digest": digest(raw.encode()), "raw": raw}], "frozen raw lock changed")
        same(chain["lockPackages"], [] if name == "malformed-lock" else sorted(lock_packages(raw)), "development/transitive frozen denominator narrowed")
        same(chain["licensePolicy"], LICENSE_POLICY, "explicit license policy changed")
        same(chain["provenanceAuthority"], {"status": "unavailable", "reason": "build-attestation-verification-owner-unavailable"}, "build authority invented")
        require("provenance" not in chain and "subjectArtifact" not in chain, "target build evidence fabricated")
        require(len(case["requests"]) == len(case["diagnostics"]) == 2, "both original native SDK attempts required")
        diagnostics = {item["record"]["receipt"]["requestId"]: item for item in case["diagnostics"]}
        require(len(diagnostics) == 2, "native receipts duplicated")
        produced = {}
        for request in case["requests"]:
            require(request["requestId"] not in seen, "native receipt identity reused")
            seen.add(request["requestId"])
            require(request["requestId"] in diagnostics, "original native diagnostic absent")
            format, receipt, output, complete = native_receipt(case, request, diagnostics[request["requestId"]], row["toolchainBefore"], live)
            key = "cyclonedx" if format == "cyclonedx-json" else "spdx"
            require(key not in produced, "dual native output format duplicated")
            produced[key] = complete
            if complete:
                same(chain["documents"].get(key), {"raw": output.decode(), "digest": digest(output), "receipt": receipt}, "native document/receipt substituted")
            else:
                require(key not in chain["documents"], "failed native scan presented as a document")
        require(set(produced) == {"cyclonedx", "spdx"}, "native format absent")
        same(case["analysis"], analyze(input), "native analysis not independently reproducible")
        require(case["analysis"]["coverageGaps"][-2:] == AUTHORITY_GAPS, "required target provenance gap removed")
        if name in ("nonempty-clean", "license-violation"):
            require(case["analysis"]["sbomLicenseComplete"] is True and case["analysis"]["reconciliation"]["expected"] == case["analysis"]["reconciliation"]["examined"] == 3, "positive nonempty full denominator incomplete")
            require(len(case["analysis"]["findings"]) == (1 if name == "license-violation" else 0), "native license decision differs")
        elif name == "unknown-license":
            require(any(gap["kind"] == "supply-chain-license-undecided" for gap in case["analysis"]["coverageGaps"]), "unknown license silently admitted")
        else:
            require(any(gap["kind"] == "dependency-manifest-unparsed" for gap in case["analysis"]["coverageGaps"]), "malformed lock silently admitted")
        if live:
            require(regular(source / "package-lock.json").read_bytes() == raw.encode(), "retained native fixture changed")
    baseline = cases[0]["input"]
    missing = cases[4]
    expected = set(baseline["artifacts"]["supplyChain"]["lockPackages"]) | {"pkg:npm/missing-package@9.0.0"}
    require(missing["kind"] == "derived-reconciliation-refusal" and missing["baseline"] == "nonempty-clean" and missing["expectedPackages"] == sorted(expected), "missing-package consumer control changed")
    documents = baseline["artifacts"]["supplyChain"]["documents"]
    same(missing["reconciliation"], reconcile(expected, documents["cyclonedx"]["raw"].encode(), documents["spdx"]["raw"].encode()), "missing package not independently rederived")
    require(missing["reconciliation"]["expected"] == 4 and missing["reconciliation"]["examined"] == 3 and missing["reconciliation"]["coverageGaps"] == [{"kind": "sbom-package-missing", "name": "pkg:npm/missing-package@9.0.0"}], "missing-package refusal differs")
    for case in cases[5:9]:
        require(case["kind"] == "derived-consumer-refusal" and case["baseline"] == "nonempty-clean", "derived refusal mislabelled native")
        expected = expected_mutation(case["control"], baseline)
        same(case["input"], expected, "consumer refusal not exact declared mutation of real native evidence")
        same(case["analysis"], analyze(expected), "consumer refusal not independently rederived")
        require(case["analysis"]["complete"] is False and case["analysis"]["coverageGaps"][-2:] == AUTHORITY_GAPS, "consumer refusal erased target provenance gap")
    require("subject-mismatch" in cases[7]["analysis"]["provenance"]["reasons"] and "malformed-statement" in cases[8]["analysis"]["provenance"]["reasons"], "artifact/provenance substitution accepted")
    for case, state in zip(cases[9:12], ("missing_executable", "unauthorized_effect", "sandbox_missing")):
        require(case["kind"] == "native-sdk-refusal", "SDK refusal replaced by synthetic summary")
        req, receipt = case["request"], case["receipt"]
        expected = copy.deepcopy(cases[0]["requests"][0])
        expected["requestId"] = "supply-chain-refusal:" + case["control"]
        if case["control"] == "tool-unavailable":
            expected.update(executable=str(path(cases[0]["root"]).parent.parent / "absent-native-syft"), args=[], versionArgs=["--version"], expectedDigest=digest(b"absent"))
        if case["control"] == "sandbox-missing":
            expected["sandbox"] = None
        same(req, expected, "refusal request differs from exact genuine baseline")
        require(receipt["state"] == state and receipt["complete"] is False and receipt["stdout"] is None and receipt["stderr"] is None and receipt["exitCode"] is None and receipt["signal"] is None and receipt["providerId"] == ID and receipt["planId"] == req["planId"], "original refused SDK receipt differs")
        same(receipt["processTree"], {"started": False, "terminated": False, "reaped": False, "hardKilled": False, "detail": None}, "refusal launched a process")
        same(receipt["timing"], {"startedAtMs": 0, "completedAtMs": 0, "durationMs": 0}, "refusal timing fabricated")
        require(receipt["receiptId"] == "receipt:" + receipt["requestId"], "refusal receipt identity differs")
        if case["control"] == "tool-unavailable":
            require(receipt["policy"] is None and receipt["executable"] is None and receipt["requestId"] == req["requestId"], "missing executable was not refused by native SDK resolver")
        elif case["control"] == "admission-unavailable":
            require(receipt["requestId"] == req["requestId"] and receipt["policy"]["id"] == "audit-native-owner-admission-v1" and receipt["policy"]["allowed"] is False and receipt["policy"]["reason"] == "native-owner-admission-unavailable" and receipt["executable"] is None, "production owner admission bypassed")
        else:
            require(re.fullmatch(r"legion-audit/[0-9a-f]{64}", receipt["requestId"]) is not None and receipt["policy"]["allowed"] is True and receipt["policy"]["id"] == "legion-supply-chain-refusal-control/1" and receipt["policy"]["digest"] == digest(encoded(req)) and receipt["executable"]["digest"] == row["toolchainBefore"]["launcher"]["digest"] and receipt["sandbox"]["required"] is True and receipt["sandbox"]["receiptId"] is None and receipt["sandbox"]["networkEnabled"] is False, "sandbox refusal bypassed")
    drift = cases[12]
    require(drift["kind"] == "native-source-refusal" and path(drift["root"]) == path(cases[0]["root"]).parent.parent / "source-drift", "native drift control missing")
    same(drift["inventory"], inventory("source-drift", fixture_lock("MIT")), "source drift frozen inventory changed")
    same(drift["snapshot"], {"complete": False, "files": {"package-lock.json": digest(fixture_lock("GPL-3.0-only").encode())}, "coverageGaps": [{"kind": "supply-chain-source-drift", "path": "package-lock.json"}]}, "source drift refusal not rederived")
    if live:
        require(regular(path(drift["root"]) / "package-lock.json").read_text() == fixture_lock("GPL-3.0-only"), "native drift artifact changed")
    return row


def tamper_refusals(root, row):
    mutations = {
        "whole-provider-promotion": lambda item: item.update(wholeProviderQualification=True),
        "target-provenance-assertion": lambda item: item.update(targetBuildProvenanceVerified=True),
        "missing-control": lambda item: item["cases"].pop(),
        "source-closure": lambda item: item["binding"]["sourceAfter"]["files"].pop(next(iter(item["binding"]["sourceAfter"]["files"]))),
        "toolchain-drift": lambda item: item["toolchainAfter"]["syft"].update(digest=digest(b"substitute")),
        "official-archive-pin": lambda item: (item["toolchainBefore"]["archive"].update(digest=digest(b"substitute")), item["toolchainAfter"]["archive"].update(digest=digest(b"substitute"))),
        "dev-denominator": lambda item: item["cases"][0]["input"]["artifacts"]["supplyChain"]["lockPackages"].remove("pkg:npm/dev-only@3.0.0"),
        "native-receipt": lambda item: item["cases"][0]["diagnostics"][0]["record"]["receipt"].update(complete=False),
        "target-gap": lambda item: item["cases"][0]["analysis"]["coverageGaps"].pop(),
        "fake-clean-license": lambda item: item["cases"][1]["analysis"].update(findings=[]),
        "source-drift-hidden": lambda item: item["cases"][12]["snapshot"].update(complete=True),
        "substituted-native-stream": lambda item: item["cases"][0]["input"]["artifacts"]["supplyChain"]["documents"]["cyclonedx"].update(raw="{}", digest=digest(b"{}")),
    }
    passed = []
    for name, mutate in mutations.items():
        changed = copy.deepcopy(row)
        mutate(changed)
        try:
            validate_record(root, sealed(changed), live=False)
        except (AssertionError, KeyError, ValueError, TypeError):
            passed.append(name)
        else:
            raise AssertionError("tampered native evidence accepted: " + name)
    return passed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    options = parser.parse_args()
    row = parsed(regular(options.receipts.resolve() / "supply-chain-native.json").read_bytes())
    validate_record(options.root, row, live=True)
    refused = tamper_refusals(options.root, row)
    print("SUPPLY_CHAIN_NATIVE_ACCURACY_SUMMARY " + encoded(summary(row, refused)).decode())

if __name__ == "__main__":
    main()
