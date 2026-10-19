#!/usr/bin/env python3
"""Offline registration gate; never imports records, promotes, invokes tools, or authenticates CI.

Maintainers must first retrieve CI evidence through authenticated GitHub access &
commit a separate verification object. Its source ownership is the trust boundary;
a run number, record assertion, or this checksum check is not authentication.
External adapters validate retained native semantics, not installed tool bytes.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import runpy

ARCHIVE = "qualification/provider-accuracy"
INDEX, SCHEMA = ARCHIVE + "/index.json", ARCHIVE + "/schema.json"
GATE = "scripts/ci/audit-qualification-records.py"
TEST = "scripts/ci/tests/test_audit_qualification_records.py"
VERSION = "legion-provider-accuracy-index/1"
VERIFY_VERSION = "legion-provider-accuracy-provenance-verification/2"
BENCH = {"legacy.security.secrets": "secret", "legacy.security.node-dependencies": "dependency_cve",
         "legacy.quality.dead-code": "dead_code", "legacy.quality.duplication": "duplication", "legacy.quality.types": "type_error"}
BENCH_MANIFEST = "engine/crates/legion-audit/tests/fixtures/bench/manifest.json"
VALIDATOR = "scripts/ci/audit-provider-accuracy.py"
# Provider, family, harness, stage & original encoding are source-owned.
BASE = "engine/crates/legion-audit/tests/"
ADAPTERS = {
    "security.scanner-shellcheck": ("shellcheck", "external_scanner_accuracy", "candidate", "native-insertion-json", "real_scanner_accuracy_shellcheck"),
    "security.scanner-zizmor": ("scanner", "additional_external_scanner_accuracy", "candidate", "native-insertion-json", "real_scanner_accuracy"),
    "security.scanner-kube-linter": ("scanner", "additional_external_scanner_accuracy", "candidate", "native-insertion-json", "real_scanner_accuracy"),
    "legacy.core.repo": ("git", "legacy_git_accuracy", "fact-output", "canonical-json", "real_legacy_git_accuracy"),
    "legacy.quality.debt-markers": ("git", "legacy_git_accuracy", "finding", "canonical-json", "real_legacy_git_accuracy"),
    "security.scanner-squawk": ("extra-scanner", "more_external_scanner_accuracy", "candidate", "native-insertion-json", "real_scanner_accuracy_squawk"),
    "security.scanner-brakeman": ("extra-scanner", "brakeman_accuracy", "candidate", "native-insertion-json", "real_scanner_accuracy_brakeman"),
    "legacy.security.github-actions-lint": ("linter", "real_legacy_linter_accuracy", "candidate", "canonical-json", "real_legacy_linter_accuracy"),
    "legacy.security.docker": ("linter", "real_legacy_linter_accuracy", "candidate", "canonical-json", "real_legacy_linter_accuracy"),
    "legacy.quality.swift-lint": ("linter", "real_legacy_linter_accuracy", "finding", "canonical-json", "real_legacy_linter_accuracy"),
    "security.scanner-tflint": ("harness-scanner", "tflint_accuracy", "candidate", "native-insertion-json", "real_scanner_accuracy_tflint"),
    "security.scanner-kubeconform": ("harness-scanner", "kubeconform_accuracy", "candidate", "native-insertion-json", "real_scanner_accuracy_kubeconform"),
    "security.scanner-golangci-lint": ("harness-scanner", "golangci_accuracy", "candidate", "native-insertion-json", "real_scanner_accuracy_golangci_lint"),
    "container.iac": ("harness-iac", "trivy_iac_accuracy", "finding", "native-insertion-json", "real_scanner_accuracy_trivy_iac"),
}
HARNESS_CONTROLS = {"security.scanner-tflint": ("tflint", "tflint", "terraform_unused_declarations|main.tf|5"),
                    "security.scanner-kubeconform": ("kubeconform", "kubeconform", "schema|pod.yaml|unresolved"),
                    "security.scanner-golangci-lint": ("golangci-lint", "golangci", "gosec|main.go|4"),
                    "container.iac": ("trivy", "trivy-iac", "DS-0002|Dockerfile")}
VALIDATORS = {"file": VALIDATOR, "shellcheck": "scripts/ci/audit-external-provider-accuracy.py",
              "scanner": "scripts/ci/audit-real-provider-accuracy.py", "git": "scripts/ci/audit-real-provider-accuracy.py",
              "extra-scanner": "scripts/ci/audit-extra-provider-accuracy.py", "linter": "scripts/ci/audit-extra-provider-accuracy.py"}
FILE_HARNESS = ["audit_cargo_test", "--test", "security_packs", "--test", "architecture_input_producer", "--test", "code_provider_accuracy",
                "--test", "suite_provider_accuracy", "--test", "legacy_file_accuracy", "--test", "artifact_provider_accuracy",
                "file_only_provider_accuracy", "--", "--nocapture", "--test-threads=1"]
BENCH_HARNESS = ["audit_cargo_test", "--test", "bench_recall", "bench_recall_qualification_receipt", "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
TFLINT_TESTS = ["scoped_ipc_rejects_long_paths_symlinks_modes_and_foreign_tools",
                "scoped_ipc_native_acl_controls_empty_allow_deny_and_lookup_failure", "scoped_ipc_native_confinement",
                "scoped_ipc_timeout_and_cancel_cleanup_after_reaping", "real_scanner_accuracy_tflint"]
ENTRY_KEYS = {"provider", "family", "record", "stage", "scope", "sourceClosure", "provenance", "provenanceVerification"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def encoded(value, mode="canonical-json"):
    require(mode in ("canonical-json", "native-insertion-json"), "unknown digest encoding")
    return json.dumps(value, sort_keys=mode == "canonical-json", ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def parsed(value, source):
    def pairs(items):
        require(len(items) == len(dict(items)), f"duplicate JSON key: {source}")
        return dict(items)
    return json.loads(value, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "non-JSON number"))


def load(path):
    return parsed(path.read_bytes(), path)


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "object fields differ")


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def relative_file(root, value):
    require(isinstance(value, str) and 0 < len(value) <= 240 and "\\" not in value and ":" not in value, "unsafe relative path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and ".." not in path.parts and len(path.parts) <= 12, "escaping/noncanonical path")
    current = root
    for part in path.parts:
        current /= part
        require(not current.is_symlink(), f"symlink refused: {value}")
    require(current.is_file(), f"missing source/record: {value}")
    return current


def reference(root, ref, category, original=False):
    keys(ref, {"path", "sha256", "qualificationDigest", "encoding"} if original else {"path", "sha256"})
    require(ref["path"].startswith(f"{ARCHIVE}/{category}/") and is_digest(ref["sha256"]), "retained reference differs")
    path = relative_file(root, ref["path"])
    require(digest(path.read_bytes()) == ref["sha256"], "retained bytes changed")
    if original:
        require(path.suffix == ".json" and is_digest(ref["qualificationDigest"]), "record identity differs")
    return path


def helper(name):
    # Definitions only: each validator protects its executable CLI with __main__.
    return runpy.run_path(str(Path(__file__).with_name(name)))


def plan_for(root, provider):
    plan = load(relative_file(root, "bench/provider-accuracy-plan.json"))
    rows = [row for row in plan["providers"] if row["provider"] == provider]
    require(len(rows) == 1 and rows[0]["qualificationEligible"] is True, "file provider not completely measurable")
    return rows[0]


def adapter(root, entry):
    provider = entry["provider"]
    if provider in BENCH:
        require(entry["family"] == "bench-known-answer" and entry["stage"] == "outcome", "bench projection adapter/stage differs")
        return "bench-known-answer", "bench_recall", "canonical-json", "bench_recall_qualification_receipt"
    if provider in ADAPTERS:
        family, harness, stage, mode, selector = ADAPTERS[provider]
        require(entry["family"] == family and entry["stage"] == stage, "provider adapter/stage differs")
        return family, harness, mode, selector
    require(entry["family"] == "file" and entry["stage"] == plan_for(root, provider)["stage"], "unsupported provider adapter")
    return "file", None, "canonical-json", None


def closure_paths(root, entry):
    family, harness, _, _ = adapter(root, entry)
    paths = {GATE, TEST, SCHEMA, ".github/workflows/ci.yml", "scripts/ci/right-git-ci.sh"}
    if family in VALIDATORS:
        paths.add(VALIDATORS[family])
    if family == "bench-known-answer":
        paths.add(BASE + harness + ".rs")
        paths.add(BENCH_MANIFEST)
        fixtures = root / BASE / "fixtures/bench"
        for path in fixtures.rglob("*"):
            require(not path.is_symlink(), "symlink in bench fixture closure")
            if path.is_file():
                paths.add(path.relative_to(root).as_posix())
    elif family == "file":
        paths.update(plan_for(root, entry["provider"])["fixtures"])
        paths.add("bench/provider-accuracy-plan.json")
    else:
        paths.add(BASE + harness + ".rs")
        paths.add(VALIDATORS["shellcheck"])
        if family in ("extra-scanner", "linter", "harness-scanner", "harness-iac"):
            paths.add(VALIDATORS["scanner"])
    return sorted(paths)


def source_closure(root, entry):
    keys(entry["sourceClosure"], {"sources", "digest"})
    wanted = {path: digest(relative_file(root, path).read_bytes()) for path in closure_paths(root, entry)}
    same(entry["sourceClosure"]["sources"], wanted, "source closure stale/incomplete")
    require(entry["sourceClosure"]["digest"] == digest(encoded(wanted)), "source closure digest differs")


def summary_projection(value, family, provider):
    if family == "file":
        return value.get(provider)
    if family == "shellcheck":
        return value if value.get("provider") == provider else None
    keys(value, {"records", "modelCalls"})
    require(type(value["modelCalls"]) is int and value["modelCalls"] == 0 and isinstance(value["records"], list), "validator summary shape differs")
    ids = [item["provider"] for item in value["records"]]
    require(len(ids) == len(set(ids)), "duplicate provider in validator summary")
    matching = [item for item in value["records"] if item["provider"] == provider]
    return matching[0] if matching else None


def log_evidence(log, row, validated, family):
    emissions, summaries = [], []
    emission = "LEGION_BENCH_KNOWN_ANSWER_RECORD" if family == "bench-known-answer" else "FILE_PROVIDER_ACCURACY" if family == "file" else "LEGACY_GIT_PROVIDER_ACCURACY" if family == "git" else "LEGACY_LINTER_PROVIDER_ACCURACY" if family == "linter" else "EXTERNAL_PROVIDER_ACCURACY"
    summary = "FILE_PROVIDER_ACCURACY_SUMMARY" if family == "file" else "EXTERNAL_PROVIDER_ACCURACY_SUMMARY" if family == "shellcheck" else "REAL_PROVIDER_ACCURACY_SUMMARY" if family in ("scanner", "git") else "EXTRA_PROVIDER_ACCURACY_SUMMARY"
    for number, line in enumerate(log.read_text(encoding="utf-8").splitlines(), 1):
        for prefix, collection in ((emission + " ", emissions), (summary + " ", summaries)):
            position = line.find(prefix)
            if position >= 0:
                collection.append((number, parsed(line[position + len(prefix):], log)))
    originals = emissions if family == "bench-known-answer" else [(number, value) for number, value in emissions if value["provider"] == row["provider"]]
    require(len(originals) == 1, "CI log missing/duplicate original record emission")
    same(originals[0][1], row, "CI log original record differs")
    if family in ("harness-scanner", "harness-iac", "bench-known-answer"):
        return None, originals[0][0], None
    successful = [(number, value) for number, value in summaries if summary_projection(value, family, row["provider"]) is not None]
    require(len(successful) == 1, "CI log missing/duplicate successful validator summary")
    same(summary_projection(successful[0][1], family, row["provider"]), validated, "CI validator summary differs from validated record")
    return digest(encoded(successful[0][1])), originals[0][0], successful[0][0]


def terminal_checks(log, proof, record, summary_digest, original_line, summary_line):
    lines = log.read_bytes().splitlines(keepends=True)
    starts, ends = {}, {}
    for number, raw in enumerate(lines, 1):
        line = raw.decode("utf-8").rstrip("\r\n")
        begin, end = "AUDIT_QUALIFICATION_COMMAND_BEGIN ", "AUDIT_QUALIFICATION_COMMAND_END "
        if begin in line:
            value = parsed(line.split(begin, 1)[1], log)
            keys(value, {"sequence", "argv"})
            sequence = value["sequence"]
            require(type(sequence) is int and sequence > 0 and sequence not in starts, "duplicate/invalid command sequence")
            starts[sequence] = (number, value["argv"])
        if end in line:
            match = re.fullmatch(r"([1-9][0-9]*) ([0-9]+)", line.split(end, 1)[1])
            require(match is not None, "malformed terminal command marker")
            sequence, status = map(int, match.groups())
            require(sequence not in ends, "duplicate command terminal marker")
            ends[sequence] = (number, status)
    checks = []
    roles = [("harness", original_line)] + ([("validator", summary_line)] if summary_line is not None else [])
    for role, evidence_line in roles:
        selected = [(seq, start) for seq, start in starts.items() if start[1] == proof["command"][role]]
        require(len(selected) == 1, "missing/retried exact qualification command")
        sequence, (start, command) = selected[0]
        require(sequence in ends, "qualification command never terminated")
        end, status = ends[sequence]
        require(start < evidence_line < end and status == 0, "qualification command failed/cancelled or evidence outside span")
        if summary_line is None:
            span = b"".join(lines[start:end - 1]).decode("utf-8")
            outcomes = re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", span)
            expected_tests = TFLINT_TESTS if command == ["audit_tflint_qualification"] else [command[3]]
            require(outcomes == [("1", "0", "0")] * len(expected_tests), "required harness tests did not execute exactly once successfully")
            for test in expected_tests:
                require(len(re.findall(r"\btest (?:[A-Za-z0-9_]+::)*" + re.escape(test) + r" \.\.\.", span)) == 1,
                        "required harness test name missing/duplicated")
        check = {"role": role, "command": command, "conclusion": "success", "exitCode": 0, "sequence": sequence,
                 "logStartLine": start, "logEndLine": end, "logSpanSha256": digest(b"".join(lines[start - 1:end])), "recordSha256": record["sha256"]}
        if role == "validator":
            check["summaryDigest"] = summary_digest
        checks.append(check)
    if len(checks) == 2:
        require(checks[0]["logEndLine"] < checks[1]["logStartLine"], "harness/validator spans overlap or reordered")
    return checks


def provenance(root, entry, row, validated):
    proof, record = entry["provenance"], entry["record"]
    keys(proof, {"repository", "runId", "runAttempt", "jobId", "jobName", "jobConclusion", "workflow", "commit", "platform", "command", "validator", "log"})
    require(proof["repository"] == "Orthic-Labs/legion" and proof["workflow"] == ".github/workflows/ci.yml"
            and all(type(proof[key]) is int and proof[key] > 0 for key in ("runId", "runAttempt", "jobId"))
            and re.fullmatch(r"[0-9a-f]{40}", proof["commit"] or "") and proof["platform"] in ("macos-15", "windows-2025"), "CI provenance identity differs")
    require(isinstance(proof["jobName"], str) and 0 < len(proof["jobName"]) <= 200, "CI job missing")
    require(proof["jobConclusion"] in ("success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral", "startup_failure", "stale"), "CI job conclusion missing")
    family, harness, _, selector = adapter(root, entry)
    harness_only = family in ("harness-scanner", "harness-iac", "bench-known-answer")
    keys(proof["command"], {"harness"} if harness_only else {"harness", "validator"})
    validator = VALIDATORS.get(family)
    for args in proof["command"].values():
        require(isinstance(args, list) and 0 < len(args) <= 100 and all(isinstance(arg, str) and 0 < len(arg) <= 4096 for arg in args), "CI command missing")
    wanted_harness = (FILE_HARNESS if family == "file" else BENCH_HARNESS if family == "bench-known-answer" else ["audit_tflint_qualification"] if entry["provider"] == "security.scanner-tflint" else
                      ["audit_cargo_test", "--test", harness, selector, "--", "--ignored", "--nocapture", "--test-threads=1"])
    same(proof["command"]["harness"], wanted_harness, "CI harness selector differs")
    if harness_only:
        require(proof["validator"] is None, "harness-only proof must not invent independent validator")
    else:
        require(proof["command"]["validator"][:2] == ["python3", validator], "CI validator command differs")
        options = ["--root", "--receipts"] if family in ("file", "shellcheck") else ["--root", "--scanner-receipts", "--git-receipts"] if family in ("scanner", "git") else ["--root", "--squawk-receipts", "--brakeman-receipts", "--linter-receipts"]
        args = proof["command"]["validator"]
        require(len(args) == 2 + 2 * len(options) and args[2::2] == options, "CI validator flags differ")
        keys(proof["validator"], {"path", "sha256"})
        require(proof["validator"] == {"path": validator, "sha256": digest(relative_file(root, validator).read_bytes())}, "CI validator stale")
    log = reference(root, proof["log"], "logs")
    summary_digest, original_line, summary_line = log_evidence(log, row, validated, family)
    checks = terminal_checks(log, proof, record, summary_digest, original_line, summary_line)
    verified_path = reference(root, entry["provenanceVerification"], "verification")
    verified = load(verified_path)
    expected = {"schema": VERIFY_VERSION, "method": "authenticated-github-retrieval", "verified": True,
                "repository": proof["repository"], "runId": proof["runId"], "runAttempt": proof["runAttempt"], "jobId": proof["jobId"],
                "workflow": proof["workflow"], "commit": proof["commit"], "platform": proof["platform"], "jobConclusion": proof["jobConclusion"],
                "qualificationConclusion": "success", "checks": checks, "recordSha256": record["sha256"],
                "validationBasis": "source-owned-harness-success" if harness_only else "native-family-validator",
                "provenanceDigest": digest(encoded(proof)), "logSha256": proof["log"]["sha256"], "validatorSha256": None if harness_only else proof["validator"]["sha256"],
                "sourceClosureDigest": entry["sourceClosure"]["digest"], "summaryDigest": summary_digest}
    # This maintainer-owned attestation is required even when every CI id exists.
    # Root populates it only after authenticated retrieval; the gate creates none.
    same(verified, expected, "missing/unverified/source-unbound authenticated CI retrieval")
    return {proof["log"]["path"], entry["provenanceVerification"]["path"]}


def record_binding(root, entry, path, row, registry):
    provider = entry["provider"]
    family, _, _, _ = adapter(root, entry)
    if family == "file":
        return helper("audit-provider-accuracy.py")["validate"](root, path.parent, {provider: plan_for(root, provider)})[provider]
    require(entry["provenance"]["platform"] == "macos-15", "external native platform differs")
    if family == "bench-known-answer":
        validate_bench_record(root, entry, row, registry)
        return None
    if family == "shellcheck":
        return helper("audit-external-provider-accuracy.py")["validate_record"](root, row, live=False)
    api = helper("audit-real-provider-accuracy.py")
    files = api["sources"](root)
    if family in ("harness-scanner", "harness-iac"):
        validate_harness_record(root, entry, row, registry, files, api)
        return None
    if family in ("scanner", "git"):
        return api["validate_records"](root, [row], registry, files, git=family == "git", live=False)[0]
    return helper("audit-extra-provider-accuracy.py")["validate_records"](root, [row], registry, files, live=False)[0]


def validate_bench_record(root, entry, row, registry):
    """Known-answer class projection; native matching remains Rust-harness-owned."""
    provider, bench_class = entry["provider"], BENCH[entry["provider"]]
    projections = row["results"]
    require([item["benchClass"] for item in projections] == list(BENCH.values()) + ["drift"]
            and all(item["status"] == "pass" and item["productionQualification"] is False for item in projections), "bench class execution incomplete")
    for item in projections:
        if item["benchClass"] == "drift":
            require(item["claimScope"] == "bench-local-comparator" and "projectionDigest" not in item, "drift cannot qualify production provider")
        else:
            projection = {key: value for key, value in item.items() if key != "projectionDigest"}
            require(item["claimScope"] == "known-answer-fixture-cases" and item["projectionDigest"] == digest(encoded(projection)), "bench class projection digest differs")
    selected = next(item for item in projections if item["benchClass"] == bench_class)
    manifest_path = relative_file(root, BENCH_MANIFEST)
    manifest = load(manifest_path)
    expected_cases = [item for item in manifest["entries"] if item["class"] == bench_class]
    cases = selected["cases"]
    require([item["caseId"] for item in cases] == [item["id"] for item in expected_cases]
            and {item["planted"] for item in expected_cases} == {False, True}, "bench manifest controls missing/duplicated")
    source_files = {}

    def collect(path):
        require(not path.is_symlink(), "symlink in bench implementation closure")
        if path.is_dir():
            for child in path.iterdir():
                collect(child)
        elif path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative == "src/registry/providers.json":
                value = load(path)
                for spec in value["providers"]:
                    spec.pop("benchmark")
                source_files[relative] = digest(encoded(value))
            else:
                source_files[relative] = digest(path.read_bytes())

    for crate in (root / "engine/crates").iterdir():
        require(not crate.is_symlink(), "symlink crate refused")
        if crate.is_dir():
            collect(crate / "src")
            collect(crate / "Cargo.toml")
    for path in ("engine/Cargo.toml", "engine/Cargo.lock", "src/registry", BASE + "bench_recall.rs"):
        collect(root / path)
    binding = {"kind": "workspace-production-source-closure", "files": source_files,
               "sanitized": {"src/registry/providers.json": "remove providers[*].benchmark before canonical digest"}}
    spec = {key: value for key, value in registry[provider].items() if key != "benchmark"}
    spec.setdefault("lensIds", [])
    for case, expected in zip(cases, expected_cases):
        require(case["planted"] is expected["planted"] and case["fixture"] == expected["file"]
                and case["manifestDigest"] == digest(manifest_path.read_bytes()), "bench control identity differs")
        same(case["classification"], {"eligible": True, "passed": True}, "bench control ineligible/failed")
        fixture_dir = root / BASE / "fixtures/bench" / expected["file"].removeprefix("fixtures/").split("/")[0]
        fixtures = []
        for path in fixture_dir.rglob("*"):
            require(not path.is_symlink(), "symlink fixture refused")
            if path.is_file():
                fixtures.append({"path": path.relative_to(fixture_dir).as_posix(), "digest": digest(path.read_bytes())})
        fixtures.sort(key=lambda item: item["path"])
        same(case["fixtureFiles"], fixtures, "bench fixture byte inventory stale")
        require(case["fixtureFilesDigest"] == digest(encoded(fixtures)), "bench fixture aggregate stale")
        bound = case["implementationBinding"]
        same(bound, {"providerDefinition": spec, "providerDefinitionDigest": digest(encoded(spec)),
                     "sourceBindings": binding, "sourceBindingsDigest": digest(encoded(binding))}, "bench production binding stale")
        same({key: value for key, value in case["shippedProviderSpec"].items() if key != "benchmark"}, spec, "bench shipped provider differs")
        planned = case["frozenPlan"]["providers"]
        result = case["providerResult"]
        require(len(planned) == 1 and planned[0]["id"] == provider and planned[0]["version"] == spec["providerVersion"]
                and result["provider"] == provider and result["applicable"] is True and result["complete"] is True
                and result["status"] in ("ok", "complete") and result["coverage_gaps"] == result["degradation"] == [], "bench native result incomplete")
        coverage, receipt = result["coverage"], result["details"]["executionReceipt"]
        require(coverage["expected"] > 0 and coverage["examined"] == coverage["expected"] and coverage["gaps"] == []
                and coverage["expected"] == planned[0]["configuration"]["denominatorCount"]
                and coverage["denominator_digest"] == planned[0]["configuration"]["denominatorDigest"], "bench frozen denominator differs")
        require(receipt["complete"] is True and receipt["state"] == "completed" and receipt["gaps"] == []
                and receipt["executable"]["version"]["qualified"] is True
                and receipt["processTree"]["started"] is True and receipt["processTree"]["reaped"] is True, "bench native receipt incomplete")
        for artifact in case["retainedArtifacts"].values():
            if artifact["state"] == "retained":
                data = bytes.fromhex(artifact["bytesHex"])
                require(artifact["reference"]["digest"] == digest(data) and artifact["reference"]["bytes"] == len(data), "bench retained artifact bytes differ")


def validate_harness_record(root, entry, row, registry, files, api):
    """Bound structural checks; final Rust assertions supply this explicit proof basis."""
    provider = entry["provider"]
    family, harness, _, _ = adapter(root, entry)
    tool, case_prefix, label = HARNESS_CONTROLS[provider]
    source = relative_file(root, BASE + harness + ".rs").read_text()
    spec_items = list(registry[provider].items())
    position = next(i for i, item in enumerate(spec_items) if item[0] == "benchmark")
    spec_items[position] = spec_items[-1]
    spec_items.pop()
    bound = row["binding"]
    require(bound["providerSpecDigest"] == digest(encoded(dict(spec_items), "native-insertion-json"))
            and bound["harnessPath"] == BASE + harness + ".rs" and bound["harnessDigest"] == digest(source.encode()), "stale harness/spec binding")
    same(bound["implementation"], {"roots": api["shared"]["IMPL_TREES"], "fileCount": len(files),
                                   "digest": digest(encoded([list(pair) for pair in files], "native-insertion-json"))}, "stale native implementation binding")
    require(row["schema"] == "legion-external-provider-accuracy/1" and row["executionPath"] == "native-sdk-frozen-plan-real-external-scanner", "harness record path/schema differs")
    require(re.findall(r'"scope"\s*:\s*"([^"\n]+)"', source) == [row["scope"]], "harness claim scope differs")
    retention = re.findall(r'"receiptRetentionLimit"\s*:\s*"([^"\n]+)"', source)
    require(len(retention) == 1, "harness retention contract missing")
    cases = row["cases"]
    require([case["caseId"] for case in cases] == [case_prefix + "-planted", case_prefix + "-clean"], "harness controls missing/duplicated")
    identities = []
    for case, positive in zip(cases, (True, False)):
        same(case["expected"], [label] if positive else [], "harness expected labels differ")
        same(case["actual"], case["expected"], "harness actual output differs")
        require(case["controlMatched"] is True and case["coverageContractMatched"] is True and case["complete"] is True
                and case["coverageGaps"] == [] and case.get("expectedCoverageGaps", []) == []
                and case["receiptRetentionLimit"] == retention[0], "harness coverage/retention differs")
        require(all(is_digest(case[key]) for key in ("planDigest", "inventoryDigest")), "harness frozen identities missing")
        fixture = case["source"]
        require(fixture["path"] == label.split("|")[1] and fixture["digest"] == digest(fixture["bytes"].encode()), "harness source bytes differ")
        result, coverage, policy = case["actualProviderResult"], case["coverage"], case["policy"]
        require(result["provider"] == provider and result["applicable"] is True and result["complete"] is True
                and result["coverage_gaps"] == result["degradation"] == [] and coverage == result["coverage"]
                and coverage["expected"] == coverage["examined"] == 1 and coverage["gaps"] == []
                and is_digest(coverage["denominator_digest"]), "harness provider unavailable/incomplete")
        identity, receipt = case["toolIdentity"], case["executionReceipt"]
        go_probe = provider == "security.scanner-golangci-lint"
        probe = case["goToolchain"]["actualVersion"]["receipt"] if go_probe else identity["version"]["receipt"]
        api["executable"](identity["path"], identity["executableDigest"], live=False)
        api["executable"](policy["wrapper"]["path"], policy["wrapper"]["digest"], live=False)
        require(policy["tool"]["path"] == identity["path"] and policy["tool"]["digest"] == identity["executableDigest"]
                and policy["provider"] == provider and policy["inventoryDigest"] == case["inventoryDigest"]
                and policy["wrapper"]["path"] == "/usr/bin/sandbox-exec", "harness executable identity linkage differs")
        if go_probe:
            require(probe["state"] == "completed" and probe["complete"] is True and probe["exitCode"] == 0
                    and all(probe["processTree"][key] is True for key in ("started", "terminated", "reaped"))
                    and probe["policyId"] == policy["id"] and probe["sandbox"]["required"] is True
                    and probe["sandbox"]["networkEnabled"] is True, "Go native version probe incomplete")
        else:
            api["native"](probe, policy["id"], policy, api["compact"])
        decisions = case["policyDecisions"]
        require(len(decisions) == 2 and all(item["allowed"] is True and item["providerId"] == provider
                and item["planId"] == case["inventoryDigest"] for item in decisions), "harness native admissions missing")
        require(probe["requestId"] == decisions[0]["requestId"] and probe["executable"]["path"] == policy["wrapper"]["path"]
                and probe["executable"]["digest"] == policy["wrapper"]["digest"]
                and receipt["receiptId"] == "receipt:" + decisions[1]["requestId"] and receipt["state"] == "completed"
                and receipt["complete"] is True and receipt["executableDigest"] == identity["executableDigest"]
                and receipt["policyId"] == policy["id"] and receipt["sandbox"]["required"] is True
                and is_digest(receipt["stdoutDigest"]) and receipt["stdoutBytes"] > 0, "harness native receipt linkage differs")
        if go_probe:
            go, decision = case["goToolchain"], decisions[0]
            api["executable"](go["binary"], go["digest"], live=False)
            go_banner = go["actualVersion"]["version"]
            require(go_banner.startswith("go version " + go["requiredVersion"] + " darwin/")
                    and probe["stdout"]["raw"] == go_banner and probe["stdout"]["immutable"] is True
                    and is_digest(probe["stdout"]["digest"]) and probe["stdout"]["bytes"] >= len(go_banner.encode())
                    and probe["providerId"] == provider and probe["planId"] == case["inventoryDigest"]
                    and probe["taskId"] == decision["taskId"] == "go-version-probe" and probe["cwd"] == policy["root"]
                    and decision["args"] == decision["versionArgs"] and decision["args"][-2:] == [go["binary"], "version"],
                    "Go native toolchain version linkage differs")
            # Go probe retains trimmed output & original artifact digest, not raw bytes.
            banner = identity["version"]
            require(isinstance(banner, str) and banner.startswith(policy["tool"]["versionPrefix"])
                    and receipt["tool"]["version"] == banner, "golangci reduced scanner version linkage differs")
        else:
            for stream in ("stdout", "stderr"):
                api["artifact"](probe[stream], probe[stream]["raw"])
            banner = identity["version"]["rawVersionOutput"].strip()
            require(banner and probe["executable"]["version"]["output"].strip() == banner, "harness native version linkage differs")
        identities.append((identity["path"], identity["executableDigest"], banner))
        if family == "harness-scanner":
            require(result["findings"] == [] and receipt == result["details"]["executionReceipt"]
                    and receipt["tool"]["name"] == tool, "candidate harness stage differs")
            labels = [f"{item['ruleId']}|{item['path']}|{item['line'] if item['line'] is not None else 'unresolved'}" for item in result["details"]["candidates"]]
            require(all(item["adjudication"] == "required" for item in result["details"]["candidates"]), "candidate harness promoted adjudication")
        else:
            require(row["outputKind"] == "findings" and receipt == result["details"]["producer"] and receipt["tool"] == tool
                    and result["details"]["candidates"] == [], "finding harness stage differs")
            labels = [f"{item['ruleId']}|{item['target']}" for item in result["details"]["analysis"]["findings"]]
            same(case["expectedNativeDatabaseLabel"], {"digest": digest(("trivy-builtin-checks\0" + banner).encode()),
                 "kind": "shipped-producer-formula-version-derived-not-extracted-bundle-hash"}, "Trivy version-derived database label differs")
        same(case["actual"], labels, "harness actual native projection differs")
        for extra in ("schemas", "embeddedChecks"):
            if extra in bound:
                same(case[extra], bound[extra], "harness data pin binding differs")
                same(policy[extra], bound[extra], "harness policy pin binding differs")
        if "goModule" in case:
            require(case["goModule"]["digest"] == digest(case["goModule"]["bytes"].encode()), "Go module fixture digest differs")
            go = case["goToolchain"]
            require(all(go[key] == policy["goToolchain"][key] for key in ("root", "binary", "digest"))
                    and go["requiredVersion"] == policy["goToolchain"]["version"], "Go runtime pin linkage differs")
    require(identities[0] == identities[1], "harness tool/version changed between controls")
    same(row["metrics"], {"truePositives": 1, "falsePositives": 0, "falseNegatives": 0, "precision": 1.0, "recall": 1.0,
                          "positiveCases": 1, "cleanCases": 1}, "harness duplicate-preserving metrics differ")


def controls(row, entry):
    if entry["family"] == "bench-known-answer":
        require(row["schemaVersion"] == 1 and row["kind"] == "audit-known-answer-execution-record"
                and row["family"] == "bench-known-answer" and row["productionQualification"] is False
                and row["claimScope"] == entry["scope"] == "known-answer-fixture-cases"
                and row["bench"] == "AU20-planted-findings" and row["gate"] == "legion-audit::bench_recall", "bench execution claim differs")
        return
    stage = entry["stage"]
    require(row["provider"] == entry["provider"] and row["stage"] == stage and row["status"] == "pass"
            and row["coverageState"] == "complete" and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "record incomplete/failed")
    require(row.get("coverageGaps", []) == [], "record has coverage gaps")
    if entry["family"] not in ("git", "linter"):
        require(row["qualificationEligible"] is True, "record ineligible")
    # Source-owned family validators derive eligibility from exact native contracts.


def qualification(entry):
    value = {"basis": "retained-provider-accuracy", "index": INDEX, "record": entry["record"]["path"],
            "recordSha256": entry["record"]["sha256"], "originalQualificationDigest": entry["record"]["qualificationDigest"],
            "validationBasis": "source-owned-harness-success" if entry["provider"] in HARNESS_CONTROLS or entry["family"] == "bench-known-answer" else "native-family-validator",
            "stage": entry["stage"], "scope": entry["scope"]}
    if entry["family"] == "bench-known-answer":
        value.update({"benchClass": BENCH[entry["provider"]], "productionQualification": False})
    return value


def check(root):
    root = Path(root).resolve()
    index = load(relative_file(root, INDEX))
    keys(index, {"schema", "entries"})
    require(index["schema"] == VERSION and isinstance(index["entries"], list), "index schema differs")
    schema = load(relative_file(root, SCHEMA))
    require(schema["properties"]["schema"]["const"] == VERSION, "source schema identity differs")
    registry = load(relative_file(root, "src/registry/providers.json"))["providers"]
    require(len({row["id"] for row in registry}) == len(registry), "duplicate registry provider")
    specs, entries = {row["id"]: row for row in registry}, {}
    for entry in index["entries"]:
        keys(entry, ENTRY_KEYS)
        require(entry["provider"] in specs and entry["provider"] not in entries, "unexpected/duplicate index provider")
        entries[entry["provider"]] = entry
    retained = {INDEX, SCHEMA}
    for provider, entry in entries.items():
        require(entry["stage"] in ("candidate", "finding", "fact-output", "outcome") and isinstance(entry["scope"], str) and 0 < len(entry["scope"]) <= 1000, "missing corpus claim/stage")
        source_closure(root, entry)
        path = reference(root, entry["record"], "records", original=True)
        require(path.parent.name == provider, "record directory must name provider")
        row = load(path)
        _, _, mode, _ = adapter(root, entry)
        require(entry["record"]["encoding"] == mode, "original digest encoding differs")
        claimed = row.pop("qualificationDigest")
        require(claimed == entry["record"]["qualificationDigest"] == digest(encoded(row, mode)), "original qualification digest changed")
        row["qualificationDigest"] = claimed
        controls(row, entry)
        require(row.get("claimScope") == entry["scope"] if entry["family"] == "bench-known-answer" else row["scope"] == entry["scope"], "corpus claim differs from original")
        validated = record_binding(root, entry, path, row, specs)
        retained.add(entry["record"]["path"])
        retained.update(provenance(root, entry, row, validated))
        benchmark = specs[provider]["benchmark"]
        require(benchmark["status"] == "qualified", "indexed provider not registered")
        same(benchmark["qualification"], qualification(entry), "registry qualification reference differs")
        require(benchmark["qualificationDigest"] == digest(encoded(benchmark["qualification"])), "registry qualification digest differs")
    for provider in registry:
        benchmark, name = provider["benchmark"], provider["id"]
        require(type(benchmark["requiredForCleanClaim"]) is bool, "clean-claim requirement must remain boolean")
        if name in entries:
            continue
        if name in BENCH:
            wanted = {"basis": "bench-class", "benchClass": BENCH[name], "test": "engine/crates/legion-audit/tests/bench_recall.rs",
                      "fixtures": "engine/crates/legion-audit/tests/fixtures/bench/manifest.json", "ciWorkflow": ".github/workflows/ci.yml",
                      "ciJob": "bench", "ciRunner": "macos-15", "claim": "known-answer recall: planted positive detected and negative control clean"}
            require(benchmark["status"] == "qualified", "legacy bench qualification missing")
            same(benchmark["qualification"], wanted, "legacy bench qualification changed")
            require(benchmark["qualificationDigest"] == digest(encoded(wanted)), "legacy bench digest changed")
        elif benchmark["status"] == "qualified":
            require(name in entries, "qualified provider lacks retained record")
        else:
            require(name not in entries and benchmark.get("qualification") is None and benchmark["qualificationDigest"] is None, "unqualified provider has qualification metadata")
    actual = set()
    for path in (root / ARCHIVE).rglob("*"):
        require(not path.is_symlink(), "symlink in qualification archive")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    require(actual == retained, "qualification archive inventory differs")
    return {"registeredRecords": len(entries), "legacyBenchRecords": sum(row["id"] in BENCH and row["id"] not in entries for row in registry), "promotions": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--check", action="store_true", required=True)
    args = parser.parse_args()
    print("QUALIFICATION_RECORDS_SUMMARY " + json.dumps(check(args.root), sort_keys=True, separators=(",", ":")))
