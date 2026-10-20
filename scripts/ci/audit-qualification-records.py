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
SOURCE_CLOSURE_PROFILES = "scripts/ci/source-closure-profiles.json"
REASONING_FRESHNESS_EXCLUSIONS = {
    "scripts/ci/audit-qualification-records.py": "registration-consumer",
    "scripts/ci/tests/test_audit_qualification_records.py": "registration-consumer-tests",
    "qualification/provider-accuracy/schema.json": "registration-index-schema",
    ".github/workflows/ci.yml": "ci-orchestration",
    "scripts/ci/right-git-ci.sh": "ci-orchestration",
}
BENCH = {"legacy.security.secrets": "secret", "legacy.security.node-dependencies": "dependency_cve",
         "legacy.quality.dead-code": "dead_code", "legacy.quality.duplication": "duplication", "legacy.quality.types": "type_error"}
BENCH_MANIFEST = "engine/crates/legion-audit/tests/fixtures/bench/manifest.json"
VALIDATOR = "scripts/ci/audit-provider-accuracy.py"
# Provider, family, harness, stage & original encoding are source-owned.
BASE = "engine/crates/legion-audit/tests/"
ADAPTERS = {
    "legacy.runtime.app": ("runtime-app-sdk", "runtime_app_accuracy", "finding", "canonical-json", "real_runtime_app_accuracy"),
    "framework.backend": ("backend-source-facts", "backend_source_facts", "fact-output", "canonical-json", "backend_source_native_qualification"),
    "supply-chain.license-sbom-provenance": ("supply-chain-native", "security-supply-chain-native", "candidate", "canonical-json", "native_providers::security::producer::supply_chain_qualification_tests::native_supply_chain_qualification"),
    "legacy.quality.test": ("quality-test-native", "real_quality_test_accuracy", "finding", "canonical-json", "real_quality_test_accuracy"),
    "compatibility.core": ("compatibility-report", "compatibility_report_accuracy", "fact-output", "canonical-json", "compatibility_report_native_known_answers"),
    "code.mobile": ("code-mobile-sdk", "mobile-sdk-native", "finding", "native-insertion-json", "native_providers::code::tools::mobile_sdk::tests::native::native_mobile_sdk_controls"),
    "governance.capability-ownership": ("ownership-native", "ownership_native_accuracy", "finding", "canonical-json", "ownership_native_sdk_known_answers"),
    "code.javascript": ("javascript-sdk", "real_javascript_sdk_accuracy", "finding", "canonical-json", "real_javascript_sdk_accuracy"),
    "code.long-tail": ("code-long-tail", "code_long_tail_accuracy", "finding", "canonical-json", "code_long_tail_native_qualification"),
    "secrets.current-history": ("secrets-history", "security-history-native", "finding", "canonical-json", "native_providers::security::producer::history_qualification_tests::native_current_history_qualification"),
    "legacy.security.rust-unsafe": ("cargo-geiger", "cargo_geiger_accuracy", "candidate", "canonical-json", "real_cargo_geiger_accuracy"),
    "legacy.security.rust-policy": ("cargo-deny", "cargo_deny_accuracy", "candidate", "canonical-json", "real_cargo_deny_accuracy"),
    "legacy.security.rust-advisories": ("cargo-audit-sdk", "cargo_audit_accuracy", "candidate", "canonical-json", "real_cargo_audit_accuracy"),
    "legacy.security.js-licenses": ("license-checker", "license_checker_accuracy", "candidate", "canonical-json", "real_license_checker_accuracy"),
    "legacy.quality.rust-unused-deps": ("harness-machete", "real_cargo_machete_accuracy", "finding", "canonical-json", "real_cargo_machete_accuracy"),
    "legacy.security.python-dependencies": ("pip-audit", "pip_audit_accuracy", "candidate", "canonical-json", "real_pip_audit_accuracy"),
    "legacy.security.sast": ("semgrep-sdk", "semgrep_accuracy", "candidate", "canonical-json", "real_semgrep_accuracy"),
    "legacy.stack.rust-outdated": ("harness-rust-outdated", "real_rust_outdated_accuracy", "finding", "canonical-json", "real_rust_outdated_accuracy"),
    "legacy.stack.node-outdated": ("node-outdated", "node_outdated_accuracy", "finding", "canonical-json", "real_node_outdated_accuracy"),
    "dependency.osv": ("osv-artifact", "osv_accuracy", "finding", "native-insertion-json", "real_sdk_artifact_accuracy_osv"),
    "security.opengrep": ("opengrep-artifact", "opengrep_accuracy", "candidate", "native-insertion-json", "real_sdk_artifact_accuracy_opengrep"),
    "legacy.visual.core": ("visual", "visual_accuracy", "finding", "native-insertion-json", "real_browser_accuracy_visual_regression"),
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
    "legacy.quality.build": ("harness-quality", "real_quality_command_accuracy", "finding", "canonical-json", "real_quality_command_accuracy"),
    "legacy.quality.lint": ("harness-quality", "real_quality_command_accuracy", "finding", "canonical-json", "real_quality_command_accuracy"),
    "structural.ast-grep": ("harness-ast-grep", "ast_grep_accuracy", "candidate", "canonical-json", "real_ast_grep_accuracy"),
}
# Bounded SDK records use a distinct route with original provider contracts
# & complete fixed known-answer controls; runtime limitations remain explicit.
CODE_SDK_PROVIDERS = frozenset("code." + name for name in (
    "c-family", "dotnet", "go", "javascript", "jvm", "long-tail", "mobile", "php-ruby", "python", "rust"))
HARNESS_CONTROLS = {"security.scanner-tflint": ("tflint", "tflint", "terraform_unused_declarations|main.tf|5"),
                    "security.scanner-kubeconform": ("kubeconform", "kubeconform", "schema|pod.yaml|unresolved"),
                    "security.scanner-golangci-lint": ("golangci-lint", "golangci", "gosec|main.go|4"),
                    "container.iac": ("trivy", "trivy-iac", "DS-0002|Dockerfile")}
VALIDATORS = {"supply-chain-native": "scripts/ci/audit-supply-chain-native-accuracy.py", "backend-source-facts": "scripts/ci/audit-backend-source-facts.py", "compatibility-report": "scripts/ci/validate-compatibility-report-accuracy.py", "code-php-ruby-sdk": "scripts/ci/audit-php-ruby-code-sdk-accuracy.py", "quality-test-native": "scripts/ci/audit-quality-test-accuracy.py", "code-rust-sdk": "scripts/ci/audit-rust-code-sdk-accuracy.py", "javascript-sdk": "scripts/ci/audit-javascript-sdk-accuracy.py", "code-c-family-sdk": "scripts/ci/audit-c-family-sdk-accuracy.py", "code-mobile-sdk": "scripts/ci/audit-mobile-sdk-accuracy.py", "code-jvm-sdk": "scripts/ci/audit-jvm-sdk-accuracy.py", "ownership-native": "scripts/ci/validate-ownership-native-accuracy.py", "code-python-sdk": "scripts/ci/audit-python-code-sdk-accuracy.py", "code-long-tail": "scripts/ci/audit-code-long-tail-accuracy.py", "code-sdk": "scripts/ci/audit-code-sdk-accuracy.py", "node-outdated": "scripts/ci/audit-node-outdated-accuracy.py", "harness-rust-outdated": "scripts/ci/audit-rust-outdated-provider-accuracy.py", "semgrep-sdk": "scripts/ci/audit-semgrep-provider-accuracy.py", "pip-audit": "scripts/ci/audit-pip-audit-provider-accuracy.py", "secrets-history": "scripts/ci/audit-secrets-history-provider-accuracy.py", "cargo-geiger": "scripts/ci/audit-cargo-geiger-accuracy.py", "cargo-deny": "scripts/ci/audit-cargo-deny-accuracy.py", "cargo-audit-sdk": "scripts/ci/audit-cargo-audit-provider-accuracy.py", "license-checker": "scripts/ci/audit-license-provider-accuracy.py", "harness-machete": "scripts/ci/audit-cargo-machete-provider-accuracy.py", "osv-artifact": "scripts/ci/audit-osv-artifact-accuracy.py", "opengrep-artifact": "scripts/ci/audit-opengrep-artifact-accuracy.py", "visual": "scripts/ci/audit-visual-provider-accuracy.py", "harness-ast-grep": "scripts/ci/audit-ast-grep-provider-accuracy.py", "file": VALIDATOR, "shellcheck": "scripts/ci/audit-external-provider-accuracy.py",
              "scanner": "scripts/ci/audit-real-provider-accuracy.py", "git": "scripts/ci/audit-real-provider-accuracy.py",
              "extra-scanner": "scripts/ci/audit-extra-provider-accuracy.py", "linter": "scripts/ci/audit-extra-provider-accuracy.py"}
FILE_HARNESS = ["audit_cargo_test", "--test", "security_packs", "--test", "architecture_input_producer", "--test", "code_provider_accuracy",
                "--test", "suite_provider_accuracy", "--test", "legacy_file_accuracy", "--test", "artifact_provider_accuracy",
                "file_only_provider_accuracy", "--", "--nocapture", "--test-threads=1"]
RUST_SDK_HARNESS = ["audit_cargo_test", "--test", "real_rust_code_accuracy", "real_rust_code_accuracy", "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
PHP_RUBY_SDK_HARNESS = ["audit_cargo_test", "--test", "real_php_ruby_code_command_accuracy", "real_php_ruby_code_command_accuracy", "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
PYTHON_SDK_HARNESS = ["audit_cargo_test", "--test", "real_python_code_command_accuracy", "real_python_code_command_accuracy", "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
JVM_SDK_HARNESS = ["audit_jvm_qualification"]
CODE_MOBILE_HARNESS = ["audit_cargo_test", "--lib", ADAPTERS["code.mobile"][4], "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
CODE_MOBILE_EVIDENCE = {"nativeBefore": "mobile-native-enrollment.json", "nativeAfter": "mobile-native-after.json", "sourceEnrollment": "mobile-source-enrollment.json"}
CODE_SDK_HARNESS = ["audit_cargo_test", "--test", "real_code_command_accuracy", "real_code_command_accuracy", "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
QUALITY_HARNESS = ["audit_cargo_test", "--test", "real_quality_command_accuracy", "real_quality_command_accuracy", "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
BENCH_HARNESS = ["audit_cargo_test", "--test", "bench_recall", "bench_recall_qualification_receipt", "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
SUPPLY_CHAIN_HARNESS = ["audit_cargo_test", "--lib", ADAPTERS["supply-chain.license-sbom-provenance"][4], "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
SECRETS_HISTORY_HARNESS = ["audit_cargo_test", "--lib", "native_providers::security::producer::history_qualification_tests::native_current_history_qualification", "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
RUNTIME_APP_HARNESS = ["audit_runtime_app_qualification"]
VALIDATORS["runtime-app-sdk"] = "scripts/ci/audit-runtime-app-accuracy.py"
TFLINT_TESTS = ["scoped_ipc_ci_storage_requires_private_canonical_owned_root",
                "scoped_ipc_rejects_long_paths_symlinks_modes_and_foreign_tools",
                "scoped_ipc_native_acl_controls_empty_allow_deny_and_lookup_failure",
                "scoped_ipc_failed_version_probe_preserves_lifecycle_and_namespace", "scoped_ipc_native_confinement",
                "scoped_ipc_timeout_and_cancel_cleanup_after_reaping", "real_scanner_accuracy_tflint"]
JAVASCRIPT_SDK_EVIDENCE = {"enrollment": "enrollment.json", "childExecution": "child-execution.json", "childStdout": "child.stdout.log", "childStderr": "child.stderr.log", "providerRecord": "code_javascript.json"}
CODE_SDK_EVIDENCE = {"toolchainTree": "toolchain-tree.json", "childExecution": "child-execution.json", "childStdout": "child.stdout.log", "childStderr": "child.stderr.log", "govulnEnrollment": "govulncheck-enrollment.json"}
PHP_RUBY_SDK_EVIDENCE = {"childExecution": "child-execution.json", "childStdout": "child.stdout.log", "childStderr": "child.stderr.log", "phpRubyEnrollment": "php-ruby-sdk-enrollment.json", "providerRecord": "code_php-ruby.json"}
PYTHON_SDK_EVIDENCE = {"childExecution": "child-execution.json", "childStdout": "child.stdout.log", "childStderr": "child.stderr.log", "pythonEnrollment": "python-sdk-enrollment.json", "providerRecord": "code_python.json"}
ENTRY_KEYS = {"provider", "family", "record", "stage", "scope", "sourceClosure", "provenance", "provenanceVerification"}
DOTNET_SDK_SELECTOR = "native_providers::code::tools::dotnet_sdk_accuracy::original_dotnet_sdk_contract_has_real_language_task_and_boundary_controls"
DOTNET_SDK_HARNESS = ["audit_cargo_test", "--lib", DOTNET_SDK_SELECTOR, "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]
DOTNET_SDK_EVIDENCE = {"childExecution": "child-execution.json", "childStdout": "child.stdout.log", "childStderr": "child.stderr.log", "dotnetEnrollment": "dotnet-sdk-enrollment.json", "providerRecord": "code_dotnet.json"}
VALIDATORS["dotnet-sdk"] = "scripts/ci/audit-dotnet-sdk-accuracy.py"
PAIRED_HARNESS_FAMILIES = frozenset(("harness-scanner", "harness-iac", "bench-known-answer", "harness-quality"))
PAIRED_HARNESS_VALIDATOR = "scripts/ci/audit-harness-provider-accuracy.py"
VALIDATORS.update({family: PAIRED_HARNESS_VALIDATOR for family in PAIRED_HARNESS_FAMILIES})
PAIRED_HARNESS_GROUPS = {
    "bench": tuple(BENCH),
    "quality": ("legacy.quality.build", "legacy.quality.lint"),
    "tflint": ("security.scanner-tflint",),
    "kubeconform": ("security.scanner-kubeconform",),
    "golangci": ("security.scanner-golangci-lint",),
    "trivy-iac": ("container.iac",),
}
PAIRED_HARNESS_RECEIPTS = {"bench": "bench", "quality": "quality", "tflint": "legion-tflint-accuracy",
                           "kubeconform": "legion-kubeconform-accuracy", "golangci": "legion-golangci-accuracy",
                           "trivy-iac": "legion-trivy-iac-accuracy"}


def paired_harness_group(provider):
    return next(group for group, providers in PAIRED_HARNESS_GROUPS.items() if provider in providers)


def paired_harness_entry(provider, row):
    require(provider in set(BENCH) | set(HARNESS_CONTROLS) | set(PAIRED_HARNESS_GROUPS["quality"]), "unsupported paired harness provider")
    family, stage = ("bench-known-answer", "outcome") if provider in BENCH else (ADAPTERS[provider][0], ADAPTERS[provider][2])
    return {"provider": provider, "family": family, "stage": stage,
            "scope": "known-answer-fixture-cases" if family in ("bench-known-answer", "harness-quality") else row["scope"]}


def validate_paired_harness_record(root, entry, row, registry, raw):
    """Same original native controls for CLI & offline gate; never executes tools."""
    family, _, mode, _ = adapter(root, entry)
    require(family in PAIRED_HARNESS_FAMILIES, "unsupported paired harness family")
    same(parsed(raw, "original native receipt"), row, "original native receipt bytes differ")
    unsigned = {key: value for key, value in row.items() if key != "qualificationDigest"}
    require(is_digest(row.get("qualificationDigest")) and row["qualificationDigest"] == digest(encoded(unsigned, mode)),
            "original qualification digest changed")
    controls(row, entry)
    if family == "bench-known-answer":
        validate_bench_record(root, entry, row, registry)
    else:
        api = helper("audit-real-provider-accuracy.py")
        files = api["sources"](root)
        if family == "harness-quality":
            validate_quality_record(root, entry, row, registry, files, api)
        else:
            validate_harness_record(root, entry, row, registry, files, api)
    return {"provider": entry["provider"], "family": family, "stage": entry["stage"], "scope": entry["scope"],
            "recordSha256": digest(raw), "qualificationDigest": row["qualificationDigest"],
            "validationBasis": "native-family-validator", "productionQualification": False}


def generated_session_provenance(relative):
    # Generated host evidence only; all other source-root files remain bound.
    return re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", relative) is not None


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
    if entry["family"] == "reasoning-runtime":
        return helper("audit-reasoning-runtime-registration.py")["adapter"](entry)
    if entry["family"] == "code-php-ruby-sdk":
        require(provider == "code.php-ruby" and entry["stage"] == "finding", "PHP/Ruby SDK provider/stage differs")
        return "code-php-ruby-sdk", "real_php_ruby_code_command_accuracy", "canonical-json", "real_php_ruby_code_command_accuracy"
    if entry["family"] == "dotnet-sdk":
        require(provider == "code.dotnet" and entry["stage"] == "finding", ".NET SDK provider/stage differs")
        return "dotnet-sdk", "dotnet_sdk_accuracy", "canonical-json", DOTNET_SDK_SELECTOR
    if entry["family"] == "code-rust-sdk":
        require(provider == "code.rust" and entry["stage"] == "finding" and entry["scope"] == "known-answer-fixture-cases", "Rust SDK provider/stage/scope differs")
        return "code-rust-sdk", "real_rust_code_accuracy", "canonical-json", "real_rust_code_accuracy"
    if entry["family"] == "code-jvm-sdk":
        require(provider == "code.jvm" and entry["stage"] == "finding", "JVM SDK provider/stage differs")
        return "code-jvm-sdk", "real_jvm_sdk_accuracy", "canonical-json", "real_jvm_sdk_accuracy"
    if entry["family"] == "code-c-family-sdk":
        return helper("audit-c-family-sdk-registration.py")["adapter"](entry)
    if entry["family"] == "code-python-sdk":
        require(provider == "code.python" and entry["stage"] == "finding", "Python SDK provider/stage differs")
        return "code-python-sdk", "real_python_code_command_accuracy", "canonical-json", "real_python_code_command_accuracy"
    if provider in CODE_SDK_PROVIDERS and entry["family"] == "code-sdk":
        require(entry["stage"] == "finding", "code SDK stage differs")
        return "code-sdk", "real_code_command_accuracy", "canonical-json", "real_code_command_accuracy"
    if provider in BENCH:
        require(entry["family"] == "bench-known-answer" and entry["stage"] == "outcome", "bench projection adapter/stage differs")
        return "bench-known-answer", "bench_recall", "canonical-json", "bench_recall_qualification_receipt"
    if provider == "compatibility.core":
        require(entry["scope"] == helper("validate-compatibility-report-accuracy.py")["SCOPE"], "compatibility report scope differs")
    if provider == "legacy.runtime.app":
        require(entry["scope"] == helper("audit-runtime-app-accuracy.py")["SCOPE"], "runtime app fixture scope differs")
    if provider in ADAPTERS:
        family, harness, stage, mode, selector = ADAPTERS[provider]
        require(entry["family"] == family and entry["stage"] == stage, "provider adapter/stage differs")
        return family, harness, mode, selector
    require(entry["family"] == "file" and entry["stage"] == plan_for(root, provider)["stage"], "unsupported provider adapter")
    return "file", None, "canonical-json", None


def closure_paths(root, entry):
    family, harness, _, _ = adapter(root, entry)
    paths = {GATE, TEST, SCHEMA, ".github/workflows/ci.yml", "scripts/ci/right-git-ci.sh"}
    if family == "reasoning-runtime":
        return sorted(paths | set(helper("audit-reasoning-runtime-registration.py")["source_files"](root)))
    if family == "runtime-app-sdk":
        return sorted(paths | set(helper("audit-runtime-app-accuracy.py")["source_files"](root)))
    if family in VALIDATORS:
        paths.add(VALIDATORS[family])
    if family == "code-rust-sdk":
        paths.update(helper("audit-rust-code-sdk-accuracy.py")["source_files"](root))
        paths.update({"scripts/ci/audit-code-sdk-accuracy.py", "scripts/ci/schemas/audit-rust-code-sdk-accuracy.schema.json"})
    if family == "backend-source-facts":
        paths.update(helper("audit-backend-source-facts.py")["source_files"](root))
    elif family == "quality-test-native":
        paths.update(helper("audit-quality-test-accuracy.py")["source_files"](root))
    if family == "supply-chain-native":
        # Library-owned harness; no integration-test filename exists for this label.
        paths.update(helper("audit-supply-chain-native-accuracy.py")["source_files"](root))
        paths.add(VALIDATORS["shellcheck"])
    elif family == "compatibility-report":
        paths.update(helper("validate-compatibility-report-accuracy.py")["source_manifest"](root))
    elif family == "code-c-family-sdk":
        paths.update(helper("audit-c-family-sdk-registration.py")["source_files"](root))
    elif family == "javascript-sdk":
        paths.update(helper("audit-javascript-sdk-accuracy.py")["source_files"](root))
    elif family == "code-mobile-sdk":
        paths.update(helper("audit-mobile-sdk-accuracy.py")["source_files"](root))
    elif family == "ownership-native":
        paths.update(helper("validate-ownership-native-accuracy.py")["source_files"](root))
    elif family == "code-long-tail":
        paths.update(helper("audit-code-long-tail-accuracy.py")["source_files"](root))
    elif family == "dotnet-sdk":
        paths.update(helper("audit-dotnet-sdk-accuracy.py")["source_files"](root))
        paths.add("scripts/ci/tests/test_dotnet_sdk_adapter.py")
    elif family == "code-jvm-sdk":
        paths.update(helper("audit-jvm-sdk-accuracy.py")["source_files"](root))
        paths.add("scripts/ci/tests/test_jvm_sdk_adapter.py")
    elif family == "code-php-ruby-sdk":
        paths.update(helper("audit-php-ruby-code-sdk-accuracy.py")["source_files"](root))
        paths.add("scripts/ci/audit-code-sdk-accuracy.py")
        paths.add("scripts/ci/tests/test_python_code_sdk_adapter.py")
    elif family == "code-python-sdk":
        paths.update(helper("audit-python-code-sdk-accuracy.py")["source_files"](root))
        paths.add("scripts/ci/audit-code-sdk-accuracy.py")
        paths.add("scripts/ci/tests/test_python_code_sdk_adapter.py")
    elif family == "code-sdk":
        paths.update(helper("audit-code-sdk-accuracy.py")["source_files"](root))
    elif family == "bench-known-answer":
        paths.add(BASE + harness + ".rs")
        paths.add(BENCH_MANIFEST)
        fixtures = root / BASE / "fixtures/bench"
        for path in fixtures.rglob("*"):
            require(not path.is_symlink(), "symlink in bench fixture closure")
            if path.is_file():
                paths.add(path.relative_to(root).as_posix())
    elif family == "harness-machete":
        api = helper("audit-cargo-machete-provider-accuracy.py")
        paths.update(api["source_files"](root))
        paths.update({"scripts/ci/audit-real-provider-accuracy.py", "scripts/ci/audit-external-provider-accuracy.py",
                      ".rightgit.json", "package.json", "pnpm-lock.yaml"})
    elif family == "secrets-history":
        paths.update(helper("audit-secrets-history-provider-accuracy.py")["SOURCES"])
    elif family == "pip-audit":
        api = helper("audit-pip-audit-provider-accuracy.py")
        paths.update(api["source_files"](root))
        paths.add("engine/rust-toolchain.toml")
    elif family == "harness-rust-outdated":
        api = helper("audit-rust-outdated-provider-accuracy.py")
        paths.update(api["source_files"](root))
        paths.update({"scripts/ci/audit-real-provider-accuracy.py", "scripts/ci/audit-external-provider-accuracy.py",
                      ".rightgit.json", "package.json", "pnpm-lock.yaml"})
    elif family == "harness-quality":
        paths.update({BASE + harness + ".rs", "engine/rust-toolchain.toml", VALIDATORS["shellcheck"], VALIDATORS["scanner"]})
    elif family == "harness-ast-grep":
        paths.update({BASE + harness + ".rs", VALIDATORS[family], "engine/Cargo.toml", "engine/Cargo.lock",
                      "engine/crates/legion-audit/Cargo.toml", "engine/crates/legion-effects/Cargo.toml",
                      "engine/crates/legion-provider-sdk/Cargo.toml", "engine/crates/legion-contracts/Cargo.toml",
                      "engine/crates/legion-rules/Cargo.toml"})
        for source_root in ("engine/crates/legion-audit/src", "engine/crates/legion-effects/src",
                            "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src",
                            "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls"):
            directory = root / source_root
            require(directory.is_dir() and not directory.is_symlink(), "missing/unsafe ast-grep source closure root")
            for path in directory.rglob("*"):
                require(not path.is_symlink(), "symlink in ast-grep source closure")
                if path.is_file() and not generated_session_provenance(path.relative_to(root).as_posix()):
                    paths.add(path.relative_to(root).as_posix())
        fixture_root = root / BASE / "fixtures/ast-grep"
        require(fixture_root.is_dir() and not fixture_root.is_symlink(), "missing/unsafe ast-grep fixture root")
        for path in fixture_root.rglob("*"):
            require(not path.is_symlink(), "symlink in ast-grep fixture closure")
            if path.is_file():
                paths.add(path.relative_to(root).as_posix())
    elif family == "node-outdated":
        api = helper("audit-node-outdated-accuracy.py")
        paths.update(api["SOURCE_FILES"])
        paths.update({"scripts/ci/provision-audit-node-outdated.py", "scripts/ci/tests/test_audit_node_outdated_accuracy.py"})
        paths.update({".rightgit.json", "package.json", "pnpm-lock.yaml"})
        for relative in api["SOURCE_ROOTS"]:
            directory = root / relative
            require(directory.is_dir() and not directory.is_symlink(), "missing/unsafe npm source closure root")
            for source in directory.rglob("*"):
                require(not source.is_symlink(), "symlink in npm source closure")
                if source.is_file() and not generated_session_provenance(source.relative_to(root).as_posix()):
                    paths.add(source.relative_to(root).as_posix())
    elif family == "file":
        paths.update(plan_for(root, entry["provider"])["fixtures"])
        paths.add("bench/provider-accuracy-plan.json")
    elif family == "cargo-deny":
        api = helper("audit-cargo-deny-accuracy.py")
        paths.update(api["SOURCE_FILES"])
        paths.add("scripts/ci/tests/test_audit_cargo_deny_accuracy.py")
        paths.update({".rightgit.json", "package.json", "pnpm-lock.yaml"})
        for relative in api["SOURCE_ROOTS"]:
            directory = root / relative
            require(directory.is_dir() and not directory.is_symlink(), "missing/unsafe cargo-deny source root")
            for source in directory.rglob("*"):
                require(not source.is_symlink(), "symlink in cargo-deny source closure")
                if source.is_file() and not generated_session_provenance(source.relative_to(root).as_posix()):
                    paths.add(source.relative_to(root).as_posix())
    elif family == "cargo-audit-sdk":
        api = helper("audit-cargo-audit-provider-accuracy.py")
        paths.update(api["SOURCE_FILES"])
        for relative in api["SOURCE_ROOTS"]:
            directory = root / relative
            require(directory.is_dir() and not directory.is_symlink(), "missing/unsafe cargo-audit source root")
            for source in directory.rglob("*"):
                require(not source.is_symlink(), "symlink in cargo-audit source closure")
                if source.is_file() and not generated_session_provenance(source.relative_to(root).as_posix()):
                    paths.add(source.relative_to(root).as_posix())
    elif family == "cargo-geiger":
        api = helper("audit-cargo-geiger-accuracy.py")
        paths.update(api["SOURCE_FILES"])
        paths.update({"scripts/ci/tests/test_audit_cargo_geiger_accuracy.py", "scripts/ci/provision-cargo-geiger.py", ".rightgit.json", "package.json", "pnpm-lock.yaml"})
        for relative in api["SOURCE_ROOTS"]:
            for source in (root / relative).rglob("*"):
                require(not source.is_symlink(), "symlink in cargo-geiger source closure")
                if source.is_file() and not generated_session_provenance(source.relative_to(root).as_posix()):
                    paths.add(source.relative_to(root).as_posix())
    elif family == "license-checker":
        api = helper("audit-license-provider-accuracy.py")
        paths.update(api["SOURCE_FILES"])
        for relative in api["SOURCE_ROOTS"]:
            for source in (root / relative).rglob("*"):
                require(not source.is_symlink(), "symlink in license-checker source closure")
                if source.is_file() and not generated_session_provenance(source.relative_to(root).as_posix()):
                    paths.add(source.relative_to(root).as_posix())
    elif family == "osv-artifact":
        paths.update({BASE + harness + ".rs", "engine/rust-toolchain.toml", ".rightgit.json", "package.json", "pnpm-lock.yaml"})
        api = helper("audit-osv-artifact-accuracy.py")
        paths.update(api["SOURCE_FILES"])
        for relative in api["SOURCE_ROOTS"]:
            for source in (root / relative).rglob("*"):
                require(not source.is_symlink(), "symlink in OSV source closure")
                if source.is_file() and not generated_session_provenance(source.relative_to(root).as_posix()):
                    paths.add(source.relative_to(root).as_posix())
    elif family == "semgrep-sdk":
        api = helper("audit-semgrep-provider-accuracy.py")
        paths.update(api["FILES"])
        for relative in api["TREES"]:
            directory = root / relative
            require(directory.is_dir() and not directory.is_symlink(), "Semgrep source root absent/unsafe")
            for source in directory.rglob("*"):
                require(not source.is_symlink(), "symlink in Semgrep source closure")
                if source.is_file() and not generated_session_provenance(source.relative_to(root).as_posix()):
                    paths.add(source.relative_to(root).as_posix())
    elif family == "opengrep-artifact":
        paths.update({BASE + harness + ".rs", "src/registry/rules/opengrep/legion-core.yml", "engine/rust-toolchain.toml", ".rightgit.json", "package.json", "pnpm-lock.yaml"})
    elif family == "visual":
        paths.add(BASE + harness + ".rs")
        paths.update({".rightgit.json", "package.json", "pnpm-lock.yaml"})
    else:
        paths.add(BASE + harness + ".rs")
        paths.add(VALIDATORS["shellcheck"])
        if family in ("extra-scanner", "linter", "harness-scanner", "harness-iac"):
            paths.add(VALIDATORS["scanner"])
    return sorted(paths)


def reasoning_freshness_exclusions(root):
    # Current verification policy, never a new input retroactively added to capture.
    policy = load(relative_file(root, SOURCE_CLOSURE_PROFILES))
    keys(policy, {"schema", "profiles"})
    require(policy["schema"] == "legion-provider-source-closure-profiles/1", "unknown source closure policy version")
    keys(policy["profiles"], {"reasoning-runtime-production/v1"})
    profile = policy["profiles"]["reasoning-runtime-production/v1"]
    keys(profile, {"family", "basis", "claim", "authentication", "productionQualification", "rationale", "exclusions"})
    require(profile["family"] == "reasoning-runtime" and profile["basis"] == "historical-source-map-projection"
            and profile["claim"] == "selected-producing-source-equivalence"
            and profile["authentication"] == "original-capture-and-authenticated-binary-retrieval-unchanged"
            and profile["productionQualification"] is False, "reasoning freshness policy identity/claim differs")
    require(isinstance(profile["rationale"], str) and 0 < len(profile["rationale"].strip()) <= 2000,
            "reasoning freshness policy rationale absent")
    rows = profile["exclusions"]
    require(isinstance(rows, list) and len(rows) == len(REASONING_FRESHNESS_EXCLUSIONS), "reasoning freshness exclusions differ")
    excluded = {}
    for row in rows:
        keys(row, {"path", "role", "rationale"})
        require(isinstance(row["path"], str) and row["path"] in REASONING_FRESHNESS_EXCLUSIONS
                and row["path"] not in excluded, "unknown/duplicate reasoning freshness exclusion")
        require(row["role"] == REASONING_FRESHNESS_EXCLUSIONS[row["path"]]
                and isinstance(row["rationale"], str) and 0 < len(row["rationale"].strip()) <= 2000,
                "reasoning freshness exclusion role/rationale differs")
        excluded[row["path"]] = row["role"]
    same(excluded, REASONING_FRESHNESS_EXCLUSIONS, "reasoning freshness exclusion set differs")
    return set(excluded)


def source_closure(root, entry):
    keys(entry["sourceClosure"], {"sources", "digest"})
    if entry["family"] == "reasoning-runtime":
        historical = entry["sourceClosure"]["sources"]
        require(isinstance(historical, dict) and historical, "reasoning historical source map malformed")
        for path, value in historical.items():
            require(isinstance(path, str) and 0 < len(path) <= 240 and "\\" not in path and ":" not in path
                    and is_digest(value), "reasoning historical source map malformed")
            relative = PurePosixPath(path)
            require(relative.parts and not relative.is_absolute() and str(relative) == path
                    and len(relative.parts) <= 12 and all(part not in (".", "..") for part in relative.parts),
                    "reasoning historical source path unsafe")
        require(entry["sourceClosure"]["digest"] == digest(encoded(historical)), "source closure digest differs")
        excluded = reasoning_freshness_exclusions(root)
        require(excluded <= set(historical), "reasoning historical capture exclusion paths missing")
        api = helper("audit-reasoning-runtime-registration.py")
        wanted = {path: api["source_digest"](root, path) for path in closure_paths(root, entry) if path not in excluded}
        same({path: value for path, value in historical.items() if path not in excluded}, wanted,
             "reasoning producer source closure stale/incomplete")
        return
    source_digest = helper("audit-supply-chain-native-accuracy.py")["source_digest"] if entry["family"] == "supply-chain-native" else helper("validate-compatibility-report-accuracy.py")["source_digest"] if entry["family"] == "compatibility-report" else helper("audit-jvm-sdk-accuracy.py")["source_digest"] if entry["family"] == "code-jvm-sdk" else helper("audit-mobile-sdk-accuracy.py")["source_digest"] if entry["family"] == "code-mobile-sdk" else lambda base, path: digest(relative_file(base, path).read_bytes())
    wanted = {path: source_digest(root, path) for path in closure_paths(root, entry)}
    same(entry["sourceClosure"]["sources"], wanted, "source closure stale/incomplete")
    require(entry["sourceClosure"]["digest"] == digest(encoded(wanted)), "source closure digest differs")


def summary_projection(value, family, provider):
    if family == "supply-chain-native":
        return value if value.get("provider") == provider else None
    if family == "javascript-sdk":
        return value if value.get("provider") == provider else None
    if family == "file":
        return value.get(provider)
    if family == "shellcheck":
        return value if value.get("provider") == provider else None
    if family == "harness-ast-grep":
        require(value.get("providerId") == provider and value.get("caseCount") == 2 and value.get("fixtureOnly") is True,
                "ast-grep validator summary provider/control scope differs")
        return value
    keys(value, {"records", "modelCalls"})
    require(type(value["modelCalls"]) is int and value["modelCalls"] == 0 and isinstance(value["records"], list), "validator summary shape differs")
    ids = [item["provider"] for item in value["records"]]
    require(len(ids) == len(set(ids)), "duplicate provider in validator summary")
    matching = [item for item in value["records"] if item["provider"] == provider]
    return matching[0] if matching else None


def log_evidence(log, row, validated, family, code_artifact=None, provider=None):
    emissions, summaries = [], []
    provider = provider or row.get("provider", row.get("providerId"))
    emission = "SUPPLY_CHAIN_NATIVE_ACCURACY" if family == "supply-chain-native" else "BACKEND_SOURCE_FACTS_ACCURACY" if family == "backend-source-facts" else "PHP_RUBY_CODE_COMMAND_SDK_ACCURACY_ARTIFACT" if family == "code-php-ruby-sdk" else "QUALITY_TEST_NATIVE_ACCURACY" if family == "quality-test-native" else "RUST_CODE_SDK_ACCURACY_ARTIFACT" if family == "code-rust-sdk" else "C_FAMILY_SDK_ACCURACY_ARTIFACT" if family == "code-c-family-sdk" else "JAVASCRIPT_SDK_ACCURACY_ARTIFACT" if family == "javascript-sdk" else "CODE_MOBILE_SDK_ACCURACY_ARTIFACT" if family == "code-mobile-sdk" else "JVM_SDK_ACCURACY_ARTIFACT" if family == "code-jvm-sdk" else "OWNERSHIP_NATIVE_PROVIDER_ACCURACY" if family == "ownership-native" else "PYTHON_CODE_COMMAND_SDK_ACCURACY_ARTIFACT" if family == "code-python-sdk" else "CODE_LONG_TAIL_PROVIDER_ACCURACY" if family == "code-long-tail" else "CODE_COMMAND_SDK_ACCURACY_ARTIFACT" if family == "code-sdk" else "NODE_OUTDATED_PROVIDER_ACCURACY" if family == "node-outdated" else "RUST_OUTDATED_PROVIDER_ACCURACY" if family == "harness-rust-outdated" else "SEMGREP_PROVIDER_ACCURACY" if family == "semgrep-sdk" else "PIP_AUDIT_SDK_ACCURACY" if family == "pip-audit" else "SECRETS_HISTORY_NATIVE_QUALIFICATION" if family == "secrets-history" else "CARGO_GEIGER_PROVIDER_ACCURACY" if family == "cargo-geiger" else "CARGO_DENY_PROVIDER_ACCURACY" if family == "cargo-deny" else "CARGO_AUDIT_PROVIDER_ACCURACY" if family == "cargo-audit-sdk" else "LICENSE_CHECKER_PROVIDER_ACCURACY" if family == "license-checker" else "CARGO_MACHETE_PROVIDER_ACCURACY" if family == "harness-machete" else "OSV_SDK_ARTIFACT_ACCURACY" if family == "osv-artifact" else "OPENGREP_SDK_ARTIFACT_ACCURACY" if family == "opengrep-artifact" else "AST_GREP_PROVIDER_ACCURACY" if family == "harness-ast-grep" else "QUALITY_COMMAND_SDK_ACCURACY" if family == "harness-quality" else "LEGION_BENCH_KNOWN_ANSWER_RECORD" if family == "bench-known-answer" else "FILE_PROVIDER_ACCURACY" if family == "file" else "LEGACY_GIT_PROVIDER_ACCURACY" if family == "git" else "LEGACY_LINTER_PROVIDER_ACCURACY" if family == "linter" else "EXTERNAL_PROVIDER_ACCURACY"
    summary = "SUPPLY_CHAIN_NATIVE_ACCURACY_SUMMARY" if family == "supply-chain-native" else "BACKEND_SOURCE_FACTS_ACCURACY_SUMMARY" if family == "backend-source-facts" else "PHP_RUBY_CODE_COMMAND_SDK_ACCURACY_SUMMARY" if family == "code-php-ruby-sdk" else "QUALITY_TEST_NATIVE_ACCURACY_SUMMARY" if family == "quality-test-native" else "RUST_CODE_SDK_ACCURACY_SUMMARY" if family == "code-rust-sdk" else "C_FAMILY_SDK_ACCURACY_SUMMARY" if family == "code-c-family-sdk" else "JAVASCRIPT_SDK_ACCURACY_SUMMARY" if family == "javascript-sdk" else "CODE_MOBILE_SDK_ACCURACY_SUMMARY" if family == "code-mobile-sdk" else "JVM_SDK_ACCURACY_SUMMARY" if family == "code-jvm-sdk" else "OWNERSHIP_NATIVE_PROVIDER_ACCURACY_SUMMARY" if family == "ownership-native" else "PYTHON_CODE_COMMAND_SDK_ACCURACY_SUMMARY" if family == "code-python-sdk" else "CODE_LONG_TAIL_PROVIDER_ACCURACY_SUMMARY" if family == "code-long-tail" else "CODE_COMMAND_SDK_ACCURACY_SUMMARY" if family == "code-sdk" else "NODE_OUTDATED_PROVIDER_ACCURACY_SUMMARY" if family == "node-outdated" else "RUST_OUTDATED_PROVIDER_ACCURACY_SUMMARY" if family == "harness-rust-outdated" else "SEMGREP_PROVIDER_ACCURACY_SUMMARY" if family == "semgrep-sdk" else "PIP_AUDIT_SDK_ACCURACY_SUMMARY" if family == "pip-audit" else "SECRETS_HISTORY_NATIVE_QUALIFICATION_SUMMARY" if family == "secrets-history" else "CARGO_GEIGER_PROVIDER_ACCURACY_SUMMARY" if family == "cargo-geiger" else "CARGO_DENY_PROVIDER_ACCURACY_SUMMARY" if family == "cargo-deny" else "CARGO_AUDIT_PROVIDER_ACCURACY_SUMMARY" if family == "cargo-audit-sdk" else "LICENSE_CHECKER_PROVIDER_ACCURACY_SUMMARY" if family == "license-checker" else "CARGO_MACHETE_PROVIDER_ACCURACY_SUMMARY" if family == "harness-machete" else "OSV_SDK_ARTIFACT_ACCURACY_SUMMARY" if family == "osv-artifact" else "OPENGREP_SDK_ARTIFACT_ACCURACY_SUMMARY" if family == "opengrep-artifact" else "AST_GREP_PROVIDER_ACCURACY_SUMMARY" if family == "harness-ast-grep" else "VISUAL_PROVIDER_ACCURACY_SUMMARY" if family == "visual" else "FILE_PROVIDER_ACCURACY_SUMMARY" if family == "file" else "EXTERNAL_PROVIDER_ACCURACY_SUMMARY" if family == "shellcheck" else "REAL_PROVIDER_ACCURACY_SUMMARY" if family in ("scanner", "git") else "EXTRA_PROVIDER_ACCURACY_SUMMARY"
    if family == "compatibility-report":
        emission, summary = "COMPATIBILITY_REPORT_PROVIDER_ACCURACY", "COMPATIBILITY_REPORT_PROVIDER_ACCURACY_SUMMARY"
    if family == "runtime-app-sdk":
        emission, summary = "RUNTIME_APP_SDK_ACCURACY", "RUNTIME_APP_SDK_ACCURACY_SUMMARY"
    emission_separator = "=" if family == "harness-ast-grep" else " "
    summary_separator = "=" if family == "harness-ast-grep" else " "
    if family == "dotnet-sdk":
        emission, summary = "DOTNET_CODE_COMMAND_SDK_ACCURACY_ARTIFACT", "DOTNET_CODE_COMMAND_SDK_ACCURACY_SUMMARY"
    if family in PAIRED_HARNESS_FAMILIES:
        require(provider is not None, "paired validator provider projection missing")
        summary = "HARNESS_PROVIDER_ACCURACY_SUMMARY"
    for number, line in enumerate(log.read_text(encoding="utf-8").splitlines(), 1):
        for prefix, collection in ((emission + emission_separator, emissions), (summary + summary_separator, summaries)):
            position = line.find(prefix)
            if position >= 0:
                collection.append((number, parsed(line[position + len(prefix):], log)))
    originals = emissions if family == "bench-known-answer" else [(number, value) for number, value in emissions
        if value.get("provider", value.get("providerId")) == provider]
    require(len(originals) == 1, "CI log missing/duplicate original record emission")
    same(originals[0][1], code_artifact if family in ("code-php-ruby-sdk", "dotnet-sdk", "code-rust-sdk", "javascript-sdk", "code-c-family-sdk", "code-mobile-sdk", "code-sdk", "code-python-sdk", "code-jvm-sdk") else row, "CI log original record/artifact differs")
    successful = [(number, value) for number, value in summaries if summary_projection(value, family, provider) is not None]
    require(len(successful) == 1, "CI log missing/duplicate successful validator summary")
    same(summary_projection(successful[0][1], family, provider), validated, "CI validator summary differs from validated record")
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
        paired_native = role == "harness" and (command in (BENCH_HARNESS, QUALITY_HARNESS, ["audit_tflint_qualification"])
            or command[:3] in [["audit_cargo_test", "--test", ADAPTERS[provider][1]] for provider in HARNESS_CONTROLS])
        if summary_line is None or paired_native or (role == "harness" and command == JVM_SDK_HARNESS) or (role == "harness" and command in (SUPPLY_CHAIN_HARNESS, SECRETS_HISTORY_HARNESS, CODE_MOBILE_HARNESS, DOTNET_SDK_HARNESS)) or (role == "harness" and command[:3] in (["audit_cargo_test", "--test", "ownership_native_accuracy"], ["audit_cargo_test", "--test", "backend_source_facts"], ["audit_cargo_test", "--test", "real_rust_code_accuracy"], ["audit_cargo_test", "--test", "c_family_sdk_accuracy"], ["audit_cargo_test", "--test", "code_long_tail_accuracy"], ["audit_cargo_test", "--test", "real_code_command_accuracy"], ["audit_cargo_test", "--test", "visual_accuracy"], ["audit_cargo_test", "--test", "opengrep_accuracy"], ["audit_cargo_test", "--test", "ast_grep_accuracy"], ["audit_cargo_test", "--test", "osv_accuracy"], ["audit_cargo_test", "--test", "real_cargo_machete_accuracy"], ["audit_cargo_test", "--test", "cargo_deny_accuracy"], ["audit_cargo_test", "--test", "cargo_audit_accuracy"], ["audit_cargo_test", "--test", "cargo_geiger_accuracy"], ["audit_cargo_test", "--test", "pip_audit_accuracy"], ["audit_cargo_test", "--test", "semgrep_accuracy"], ["audit_cargo_test", "--test", "real_rust_outdated_accuracy"], ["audit_cargo_test", "--test", "node_outdated_accuracy"])):
            span = b"".join(lines[start:end - 1]).decode("utf-8")
            outcomes = re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", span)
            expected_tests = ["gradle_sandbox::tests::gradle_bind_only_native_confinement", "real_jvm_sdk_accuracy"] if command == JVM_SDK_HARNESS else TFLINT_TESTS if command == ["audit_tflint_qualification"] else [command[2]] if command in (SUPPLY_CHAIN_HARNESS, SECRETS_HISTORY_HARNESS, CODE_MOBILE_HARNESS, DOTNET_SDK_HARNESS) else [command[3]]
            # Node retains & replays one child run of this same named fixture.
            expected_runs = 2 if command[:3] == ["audit_cargo_test", "--test", "node_outdated_accuracy"] else 1
            require(outcomes == [("1", "0", "0")] * (len(expected_tests) * expected_runs), "required harness tests did not execute expected successful count")
            for test in expected_tests:
                require(len(re.findall(r"\btest (?:[A-Za-z0-9_]+::)*" + re.escape(test) + r" \.\.\.", span)) == expected_runs,
                        "required harness test name missing/duplicated")
        if role == "harness" and command[:3] == ["audit_cargo_test", "--test", "ownership_native_accuracy"]:
            # --nocapture can place native JSON between named prefix & final ok.
            native_span = re.sub(r"(?m)^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z[ \t]+", "", span.replace("\r\n", "\n"))
            named = re.search(r"(?m)^test (?:[A-Za-z0-9_]+::)*ownership_native_sdk_known_answers \.\.\.", native_span)
            summary = re.search(r"(?m)^test result: ok\.", native_span)
            require(named is not None and summary is not None and named.end() < summary.start(),
                    "ownership native named test/summary order differs")
            statuses = re.findall(r"(?m)^[ \t]*(ok|FAILED|ignored)(?:[ \t].*)?$", native_span[named.end():summary.start()])
            require(statuses == ["ok"], "ownership native named test did not pass exactly once")
        if role == "harness" and command == ["audit_compatibility_report_qualification"]:
            span = b"".join(lines[start:end - 1]).decode("utf-8")
            require(re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", span) == [("1", "0", "0")],
                    "compatibility report native test did not pass exactly once")
            require(len(re.findall(r"\btest compatibility_report_native_known_answers \.\.\.", span)) == 1,
                    "compatibility report native test selector missing/duplicated")
        if role == "harness" and command == RUNTIME_APP_HARNESS:
            span = b"".join(lines[start:end - 1]).decode("utf-8")
            require(re.findall(r"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", span) == [("1", "0", "0")],
                    "runtime app native test did not pass exactly once")
            require(len(re.findall(r"\btest real_runtime_app_accuracy \.\.\.", span)) == 1,
                    "runtime app native test selector missing/duplicated")
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
    keys(proof["command"], {"harness", "validator"})
    validator = VALIDATORS.get(family)
    for args in proof["command"].values():
        require(isinstance(args, list) and 0 < len(args) <= 100 and all(isinstance(arg, str) and 0 < len(arg) <= 4096 for arg in args), "CI command missing")
    wanted_harness = (SUPPLY_CHAIN_HARNESS if family == "supply-chain-native" else PHP_RUBY_SDK_HARNESS if family == "code-php-ruby-sdk" else RUST_SDK_HARNESS if family == "code-rust-sdk" else helper("audit-c-family-sdk-registration.py")["HARNESS_COMMAND"] if family == "code-c-family-sdk" else CODE_MOBILE_HARNESS if family == "code-mobile-sdk" else JVM_SDK_HARNESS if family == "code-jvm-sdk" else PYTHON_SDK_HARNESS if family == "code-python-sdk" else CODE_SDK_HARNESS if family == "code-sdk" else SECRETS_HISTORY_HARNESS if family == "secrets-history" else FILE_HARNESS if family == "file" else QUALITY_HARNESS if family == "harness-quality" else BENCH_HARNESS if family == "bench-known-answer" else ["audit_tflint_qualification"] if entry["provider"] == "security.scanner-tflint" else
                      ["audit_cargo_test", "--test", harness, selector, "--", "--ignored", "--nocapture", "--test-threads=1"])
    if family in ("backend-source-facts", "quality-test-native", "javascript-sdk", "ownership-native", "code-long-tail", "visual", "harness-ast-grep", "opengrep-artifact", "osv-artifact", "harness-machete", "license-checker", "cargo-deny", "cargo-audit-sdk", "cargo-geiger", "pip-audit", "semgrep-sdk", "harness-rust-outdated", "node-outdated"):
        wanted_harness.insert(wanted_harness.index("--nocapture"), "--exact")
    if family == "dotnet-sdk":
        wanted_harness = DOTNET_SDK_HARNESS
    if family == "compatibility-report":
        wanted_harness = ["audit_compatibility_report_qualification"]
    if family == "runtime-app-sdk":
        wanted_harness = RUNTIME_APP_HARNESS
    same(proof["command"]["harness"], wanted_harness, "CI harness selector differs")
    require(proof["command"]["validator"][:2] == ["python3", validator], "CI validator command differs")
    if family == "quality-test-native":
        args = proof["command"]["validator"]
        require(len(args) == 8 and Path(args[4]).is_absolute(), "native test validator repository root missing")
        same(args, ["python3", validator, row["evidenceRoot"] + "/legacy_quality_test.json", "--repository-root", args[4], "--evidence-root", row["evidenceRoot"], "--mutation-checks"], "native test validator exact selector differs")
    else:
        options = ["--root", "--receipts"] if family in ("supply-chain-native", "backend-source-facts", "code-php-ruby-sdk", "code-rust-sdk", "javascript-sdk", "code-c-family-sdk", "code-mobile-sdk", "code-jvm-sdk", "ownership-native", "code-python-sdk", "code-long-tail", "code-sdk", "file", "shellcheck", "visual", "secrets-history", "harness-ast-grep", "opengrep-artifact", "osv-artifact", "harness-machete", "license-checker", "cargo-deny", "cargo-audit-sdk", "cargo-geiger", "pip-audit", "semgrep-sdk", "harness-rust-outdated", "node-outdated") else ["--root", "--scanner-receipts", "--git-receipts"] if family in ("scanner", "git") else ["--root", "--squawk-receipts", "--brakeman-receipts", "--linter-receipts"]
        args = proof["command"]["validator"]
        if family == "dotnet-sdk":
            options = ["--root", "--receipts"]
        if family == "compatibility-report":
            options = ["--root", "--record"]
        if family == "runtime-app-sdk":
            options = ["--root", "--receipts"]
        if family in PAIRED_HARNESS_FAMILIES:
            options = ["--root", "--receipts", "--group"]
        require(len(args) == 2 + 2 * len(options) and args[2::2] == options, "CI validator flags differ")
        if family in PAIRED_HARNESS_FAMILIES:
            group = paired_harness_group(entry["provider"])
            require(Path(args[3]).is_absolute() and Path(args[5]).is_absolute()
                    and args[7] == group
                    and args[5].endswith("/legion-provider-qualification/" + PAIRED_HARNESS_RECEIPTS[group]),
                    "paired validator original receipt selector differs")
    if family == "supply-chain-native":
        require(Path(args[3]).is_absolute() and args[5] == str(PurePosixPath(row["cases"][0]["root"]).parent.parent)
                and args[5].endswith("/legion-provider-qualification/supply-chain-native"), "supply-chain native original receipt root differs")
    if family == "code-c-family-sdk":
        require(Path(args[3]).is_absolute() and args[5] == str(helper("audit-c-family-sdk-registration.py")["receipt_root"](row))
                and args[5].endswith("/legion-provider-qualification/code-c-family"), "C-family validator original receipt root differs")
    if family == "cargo-audit-sdk":
        require(Path(args[3]).is_absolute() and args[3] == row["binding"]["repositoryRoot"] and args[5] == row["binding"]["retainedRoot"]
                and args[5].endswith("/legion-provider-qualification/cargo-audit"), "cargo-audit validator original root/receipt scope differs")
    if family == "harness-machete":
        require(Path(args[3]).is_absolute() and args[5].endswith("/legion-provider-qualification/cargo-machete"),
                "cargo-machete validator root/receipt scope differs")
    if family == "harness-rust-outdated":
        require(Path(args[3]).is_absolute() and args[5].endswith("/legion-provider-qualification/rust-outdated"),
                "rust-outdated validator root/receipt scope differs")
    if family == "compatibility-report":
        require(Path(args[3]).is_absolute() and Path(args[5]).is_absolute()
                and args[5].endswith("/legion-provider-qualification/compatibility-report/controls/compatibility.core.json"),
                "compatibility report original record path differs")
        require(row["observation"]["implementation"]["platform"]["os"] == {"macos-15": "macos", "windows-2025": "windows"}[proof["platform"]],
                "compatibility report native platform differs")
    if family == "ownership-native":
        require(Path(args[3]).is_absolute() and Path(args[5]).is_absolute()
                and args[5].endswith("/legion-provider-qualification/ownership-native"), "ownership native receipt root differs")
    if family == "backend-source-facts":
        require(Path(args[3]).is_absolute() and args[5] == row["retainedRoot"]
                and args[5].endswith("/legion-provider-qualification/backend-source"), "backend source original receipt root differs")
    if family == "runtime-app-sdk":
        require(Path(args[3]).is_absolute() and Path(args[5]).is_absolute()
                and args[5] == row["retainedRoot"] and args[5].endswith("/legion-provider-qualification/runtime-app"),
                "runtime app original receipt root differs")
    if family == "code-long-tail":
        require(Path(args[3]).is_absolute()
                and args[5] == str(PurePosixPath(row["cases"][0]["fixtureRoot"]).parent.parent)
                and args[5].endswith("/legion-provider-qualification/code-long-tail"),
                "long-tail validator original receipt root differs")
    if family == "dotnet-sdk":
        require(Path(args[3]).is_absolute() and args[5].endswith("/legion-provider-qualification/code-dotnet-sdk")
                and args[5] == str(PurePosixPath(row["cases"][0]["policyDefinition"]["scratch"]).parents[2]),
                ".NET SDK validator native receipt scope differs")
    if family == "code-rust-sdk":
        require(Path(args[3]).is_absolute() and args[5] == row["retainedRoot"] and args[5].endswith("/legion-provider-qualification/code-rust-sdk"), "Rust SDK validator original root differs")
    if family == "code-jvm-sdk":
        require(Path(args[3]).is_absolute() and args[5].endswith("/legion-provider-qualification/code-jvm-sdk"), "JVM SDK validator original receipt root differs")
    if family == "code-php-ruby-sdk":
        require(Path(args[3]).is_absolute() and args[5].endswith("/legion-provider-qualification/code-php-ruby-sdk"),
                "PHP/Ruby SDK validator root/receipt scope differs")
    if family == "code-python-sdk":
        require(Path(args[3]).is_absolute() and args[5].endswith("/legion-provider-qualification/code-python-sdk"),
                "Python SDK validator root/receipt scope differs")
    if family == "code-mobile-sdk":
        require(args[3] == row["repositoryRoot"] and args[5] == row["retainedRoot"] and args[5].endswith("/legion-provider-qualification/code-mobile"), "mobile SDK validator original root/receipt scope differs")
    if family == "javascript-sdk":
        require(Path(args[3]).is_absolute() and args[5].endswith("/legion-provider-qualification/javascript-sdk"),
                "javascript SDK validator root/receipt scope differs")
    if family == "code-sdk":
        require(Path(args[3]).is_absolute() and args[5].endswith("/legion-provider-qualification/code-sdk"),
                "code SDK validator root/receipt scope differs")
    if family == "harness-ast-grep":
        require(Path(args[3]).is_absolute() and args[5].endswith("/legion-provider-qualification/ast-grep"),
                "ast-grep validator root/receipt scope differs")
    keys(proof["validator"], {"path", "sha256"})
    require(proof["validator"] == {"path": validator, "sha256": digest(relative_file(root, validator).read_bytes())}, "CI validator stale")
    log = reference(root, proof["log"], "logs")
    code_artifact = None
    if family == "dotnet-sdk":
        raw = relative_file(root, entry["dotnetSdkEvidence"]["providerRecord"]["path"]).read_bytes()
        require(digest(raw) == entry["record"]["sha256"], "indexed .NET SDK record is not original artifact bytes")
        code_artifact = helper("audit-dotnet-sdk-accuracy.py")["artifact_locator"](row, raw)
    if family == "code-rust-sdk":
        raw = relative_file(root, entry["rustSdkEvidence"]["code_rust.json"]["path"]).read_bytes()
        require(digest(raw) == entry["record"]["sha256"], "indexed Rust record is not original bytes")
        code_artifact = helper("audit-rust-code-sdk-accuracy.py")["artifact_locator"](row, raw)
    if family == "code-jvm-sdk":
        raw = relative_file(root, entry["jvmSdkEvidence"]["code_jvm.json"]["path"]).read_bytes()
        require(digest(raw) == entry["record"]["sha256"], "indexed JVM SDK record is not original artifact bytes")
        code_artifact = helper("audit-jvm-sdk-accuracy.py")["artifact_locator"](row, raw)
    if family == "code-c-family-sdk":
        raw = relative_file(root, entry["record"]["path"]).read_bytes()
        code_artifact = helper("audit-c-family-sdk-registration.py")["locator"](root, row, raw)
    if family == "code-php-ruby-sdk":
        raw = relative_file(root, entry["phpRubySdkEvidence"]["providerRecord"]["path"]).read_bytes()
        require(digest(raw) == entry["record"]["sha256"], "indexed PHP/Ruby SDK record is not original artifact bytes")
        code_artifact = helper("audit-php-ruby-code-sdk-accuracy.py")["artifact_locator"](row, raw)
    if family == "code-python-sdk":
        raw = relative_file(root, entry["pythonSdkEvidence"]["providerRecord"]["path"]).read_bytes()
        require(digest(raw) == entry["record"]["sha256"], "indexed Python SDK record is not original artifact bytes")
        code_artifact = helper("audit-python-code-sdk-accuracy.py")["artifact_locator"](row, raw)
    if family == "javascript-sdk":
        original_path = relative_file(root, entry["javascriptSdkEvidence"]["providerRecord"]["path"])
        raw = original_path.read_bytes()
        require(digest(raw) == entry["record"]["sha256"], "indexed javascript record is not original artifact bytes")
        code_artifact = helper("audit-javascript-sdk-accuracy.py")["artifact_locator"](row, raw)
    if family == "code-sdk":
        original_path = relative_file(root, entry["codeSdkEvidence"]["providerRecords"][entry["provider"]]["path"])
        raw = original_path.read_bytes()
        require(digest(raw) == entry["record"]["sha256"], "indexed code SDK record is not original artifact bytes")
        code_artifact = helper("audit-code-sdk-accuracy.py")["artifact_locator"](row, raw)
    if family == "code-mobile-sdk":
        raw = relative_file(root, entry["record"]["path"]).read_bytes()
        code_artifact = helper("audit-mobile-sdk-accuracy.py")["artifact_locator"](row, raw)
    summary_digest, original_line, summary_line = log_evidence(log, row, validated, family, code_artifact, entry["provider"])
    checks = terminal_checks(log, proof, record, summary_digest, original_line, summary_line)
    verified_path = reference(root, entry["provenanceVerification"], "verification")
    verified = load(verified_path)
    expected = {"schema": VERIFY_VERSION, "method": "authenticated-github-retrieval", "verified": True,
                "repository": proof["repository"], "runId": proof["runId"], "runAttempt": proof["runAttempt"], "jobId": proof["jobId"],
                "workflow": proof["workflow"], "commit": proof["commit"], "platform": proof["platform"], "jobConclusion": proof["jobConclusion"],
                "qualificationConclusion": "success", "checks": checks, "recordSha256": record["sha256"],
                "validationBasis": "native-family-validator",
                "provenanceDigest": digest(encoded(proof)), "logSha256": proof["log"]["sha256"], "validatorSha256": proof["validator"]["sha256"],
                "sourceClosureDigest": entry["sourceClosure"]["digest"], "summaryDigest": summary_digest}
    # This maintainer-owned attestation is required even when every CI id exists.
    # Root populates it only after authenticated retrieval; the gate creates none.
    same(verified, expected, "missing/unverified/source-unbound authenticated CI retrieval")
    return {proof["log"]["path"], entry["provenanceVerification"]["path"]}


def backend_source_evidence(root, entry, row):
    keys(entry["backendSourceEvidence"], {"nativeStream"})
    ref = entry["backendSourceEvidence"]["nativeStream"]
    path = reference(root, ref, "evidence")
    require(ref["path"] == ARCHIVE + "/evidence/framework.backend/native-results.jsonl"
            and ref["sha256"] == row["rawStream"]["sha256"], "original backend raw stream identity differs")
    require(path.stat().st_size == row["rawStream"]["bytes"], "backend raw stream bytes differ")
    return {ref["path"]}, path.read_bytes()


def validate_semgrep_record_digest(raw_record, indexed_digest):
    actual = helper("audit-semgrep-provider-accuracy.py")["record_digest"](raw_record)
    require(actual == indexed_digest, "original Semgrep qualification digest differs")
    return actual


def record_binding(root, entry, path, row, registry, raw_record=None):
    provider = entry["provider"]
    family, _, _, _ = adapter(root, entry)
    if family == "runtime-app-sdk":
        require(entry["provenance"]["platform"] == "macos-15", "runtime app native platform differs")
        retained = path.parent / "evidence" / row["qualificationDigest"].removeprefix("sha256:")
        api = helper("audit-runtime-app-accuracy.py")
        result = api["validate_record"](root, row, live=False, retained=retained)
        result["validatorRejectionControls"] = api["rejection_controls"](root, row, retained)
        require(result["validatorRejectionControls"] == 12, "runtime app semantic rejection controls incomplete")
        return result
    if family == "backend-source-facts":
        require(entry["provenance"]["platform"] == "macos-15", "backend source native platform differs")
        _, raw = backend_source_evidence(root, entry, row)
        api = helper("audit-backend-source-facts.py")
        result = api["validate_record"](root, row, raw, live=False)
        require(api["rejection_controls"](root, row, raw) == 20, "backend semantic mutations incomplete")
        return result
    if family == "supply-chain-native":
        require(entry["provenance"]["platform"] == "macos-15", "supply-chain native platform differs")
        api = helper("audit-supply-chain-native-accuracy.py")
        api["validate_record"](root, row, live=False)
        return api["summary"](row, api["tamper_refusals"](root, row))
    if family == "quality-test-native":
        require(entry["provenance"]["platform"] == "macos-15", "native test platform differs")
        api = helper("audit-quality-test-accuracy.py")
        evidence = path.parent / "evidence" / row["qualificationDigest"].removeprefix("sha256:")
        validated = api["validate_record"](root, row, evidence_root=evidence, live=False)
        validated["rejectedResealedAttacks"] = api["mutation_checks"](root, row, evidence)
        return validated
    if family == "dotnet-sdk":
        require(entry["provenance"]["platform"] == "macos-15", ".NET SDK native platform differs")
        return helper("audit-dotnet-sdk-accuracy.py")["validate_record"](root, row, live=False, enrollment=load(relative_file(root, entry["dotnetSdkEvidence"]["dotnetEnrollment"]["path"])))
    if family == "code-rust-sdk":
        require(entry["provenance"]["platform"] == "macos-15", "Rust SDK native platform differs")
        retained = relative_file(root, entry["rustSdkEvidence"]["code_rust.json"]["path"]).parent
        return helper("audit-rust-code-sdk-accuracy.py")["validate_retained"](root, row, retained)
    if family == "code-mobile-sdk":
        require(entry["provenance"]["platform"] == "macos-15", "mobile SDK native platform differs")
        _, evidence = code_mobile_evidence(root, entry, row)
        api = helper("audit-mobile-sdk-accuracy.py")
        result = api["validate_record"](root, row, live=False, evidence=evidence)
        require(api["rejection_controls"](root, row, evidence) == result["validatorRejectionControls"], "mobile native tamper coverage differs")
        return result
    if family == "compatibility-report":
        api = helper("validate-compatibility-report-accuracy.py")
        result = api["validate"](root, row)
        result["rejectionControls"] = api["rejection_controls"](root, row)
        return result
    if family == "ownership-native":
        require(entry["provenance"]["platform"] == "macos-15", "ownership native platform differs")
        return helper("validate-ownership-native-accuracy.py")["validate_record"](root, row, live=False)
    if family == "code-c-family-sdk":
        return helper("audit-c-family-sdk-registration.py")["validate_record"](root, entry, row)
    if family == "javascript-sdk":
        require(entry["provenance"]["platform"] == "macos-15", "javascript SDK native platform differs")
        paths = {key: relative_file(root, ref["path"]) for key, ref in entry["javascriptSdkEvidence"].items()}
        return helper("audit-javascript-sdk-accuracy.py")["validate_retained"](root, row, paths, live=False)
    if family == "code-long-tail":
        require(entry["provenance"]["platform"] == "macos-15", "long-tail native platform differs")
        return helper("audit-code-long-tail-accuracy.py")["validate_record"](root, row, live=False)
    if family == "code-jvm-sdk":
        require(entry["provenance"]["platform"] == "macos-15", "JVM SDK native platform differs")
        retained = relative_file(root, entry["jvmSdkEvidence"]["code_jvm.json"]["path"]).parent
        return helper("audit-jvm-sdk-accuracy.py")["validate_record"](root, row, live=False, retained=retained)
    if family == "code-php-ruby-sdk":
        require(entry["provenance"]["platform"] == "macos-15", "PHP/Ruby SDK native platform differs")
        return helper("audit-php-ruby-code-sdk-accuracy.py")["validate_record"](root, row, live=False, enrollment=load(relative_file(root, entry["phpRubySdkEvidence"]["phpRubyEnrollment"]["path"])))
    if family == "code-python-sdk":
        require(entry["provenance"]["platform"] == "macos-15", "Python SDK native platform differs")
        return helper("audit-python-code-sdk-accuracy.py")["validate_record"](root, row, live=False, enrollment=load(relative_file(root, entry["pythonSdkEvidence"]["pythonEnrollment"]["path"])))
    if family == "code-sdk":
        require(entry["provenance"]["platform"] == "macos-15", "code SDK native platform differs")
        return helper("audit-code-sdk-accuracy.py")["validate_record"](root, row, live=False, enrollment=load(relative_file(root, entry["codeSdkEvidence"]["govulnEnrollment"]["path"])))
    if family == "file":
        return helper("audit-provider-accuracy.py")["validate"](root, path.parent, {provider: plan_for(root, provider)})[provider]
    require(entry["provenance"]["platform"] == "macos-15", "external native platform differs")
    if family in PAIRED_HARNESS_FAMILIES:
        return validate_paired_harness_record(root, entry, row, registry, path.read_bytes())
    if family == "shellcheck":
        return helper("audit-external-provider-accuracy.py")["validate_record"](root, row, live=False)
    if family == "secrets-history":
        return helper("audit-secrets-history-provider-accuracy.py")["validate_record"](root, row, live=False)
    if family == "cargo-geiger":
        return helper("audit-cargo-geiger-accuracy.py")["validate_record"](root, row, live=False)
    if family == "cargo-deny":
        return helper("audit-cargo-deny-accuracy.py")["validate_record"](root, row, live=False)
    if family == "cargo-audit-sdk":
        return helper("audit-cargo-audit-provider-accuracy.py")["validate_record"](root, row, live=False)
    if family == "license-checker":
        return helper("audit-license-provider-accuracy.py")["validate_record"](root, row, live=False)
    if family == "node-outdated":
        return helper("audit-node-outdated-accuracy.py")["validate_record"](root, row, live=False)
    if family == "osv-artifact":
        return helper("audit-osv-artifact-accuracy.py")["validate_record"](root, row, live=False)
    if family == "semgrep-sdk":
        require(isinstance(raw_record, bytes), "original Semgrep record bytes absent")
        return helper("audit-semgrep-provider-accuracy.py")["validate_record_bytes"](
            root, raw_record, expected_row=row, live=False)
    if family == "opengrep-artifact":
        return helper("audit-opengrep-artifact-accuracy.py")["validate_record"](root, row, live=False)
    if family == "visual":
        return helper("audit-visual-provider-accuracy.py")["validate_record"](root, row, live=False)
    if family == "harness-machete":
        return helper("audit-cargo-machete-provider-accuracy.py")["validate_record"](root, row, live=False)
    if family == "harness-rust-outdated":
        return helper("audit-rust-outdated-provider-accuracy.py")["validate_record"](root, row, live=False)
    if family == "harness-ast-grep":
        return helper("audit-ast-grep-provider-accuracy.py")["validate_record"](root, row, live=False)
    if family == "pip-audit":
        return helper("audit-pip-audit-provider-accuracy.py")["validate_record"](root, row, live=False)
    api = helper("audit-real-provider-accuracy.py")
    files = api["sources"](root)
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
            if generated_session_provenance(relative):
                return
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


def quality_fixtures(provider, control):
    """Source-owned corpus; no execution or generated qualification evidence."""
    source = ("pub fn answer() -> u8 { missing_name }\n" if control == "compiler-failure" else
              "use std::fmt;\npub fn answer() -> u8 { 42 }\n" if provider == "legacy.quality.build" and control == "positive" else
              "pub fn answer() -> u8 { 42 }\n" if provider == "legacy.quality.build" else
              "pub fn equal(value: i32) -> bool {\n    value == value\n}\n" if control == "positive" else
              "pub fn equal(left: i32, right: i32) -> bool {\n    left == right\n}\n")
    return {"Cargo.toml": '[package]\nname = "legion_quality_fixture"\nversion = "0.0.0"\nedition = "2021"\n[workspace]\n',
            "Cargo.lock": '# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = "legion_quality_fixture"\nversion = "0.0.0"\n',
            "rust-toolchain.toml": '[toolchain]\nchannel = "1.98.0"\nprofile = "minimal"\ncomponents = ["clippy"]\n', "src/lib.rs": source}


def validate_quality_record(root, entry, row, registry, files, api):
    """Retained SDK evidence only; successful source-owned Rust assertions remain required."""
    provider = entry["provider"]
    build = provider == "legacy.quality.build"
    harness = BASE + "real_quality_command_accuracy.rs"
    spec = {key: value for key, value in registry[provider].items() if key != "benchmark"}
    expected_sources = dict(files + [(path, digest(relative_file(root, path).read_bytes()))
                                    for path in (harness, "engine/rust-toolchain.toml")])
    bound = row["binding"]
    require(bound["fixture"] == harness and row["providerVersion"] == spec["providerVersion"]
            and row["executionPath"] == "native-sdk-frozen-plan-real-cargo"
            and row["admissionScope"] == "explicit constructed SDK authorizer; no production CLI owner-admission claim", "quality SDK path/scope differs")
    same(bound["providerSpec"], spec, "quality provider specification differs")
    require(bound["providerSpecDigest"] == digest(encoded(spec)), "quality specification stale")
    same(bound["sources"], expected_sources, "quality implementation closure stale/incomplete")
    require(bound["sourcesDigest"] == digest(encoded(expected_sources)), "quality implementation digest differs")
    cases = row["cases"]
    controls = ("positive", "absence", "compiler-failure")
    require([case["caseId"] for case in cases] == [provider.replace(".", "-") + "-" + control for control in controls], "quality controls missing/duplicated")
    fixture_sources, identities = {}, []
    for case, control in zip(cases, controls):
        positive, failed = control == "positive", control == "compiler-failure"
        wanted = quality_fixtures(provider, control)
        hashes = {path: digest(text.encode()) for path, text in wanted.items()}
        same(case["fixtureFiles"], wanted, "quality fixture bytes differ")
        same(case["fixtureSources"], hashes, "quality full fixture binding differs")
        fixture_sources.update({case["caseId"] + "/" + path: value for path, value in hashes.items()})
        require(case["provider"] == provider and case["control"] == control and case["matched"] is True
                and case["locatorPrecision"] == "case classification from actual diagnostic; native finding is aggregate summary anchor", "quality case identity/claim differs")
        inventory, planned, result = case["inventory"], case["frozenProvider"], case["nativeResult"]
        entries = [{"path": path, "symbols": [], "dependencies": [], "packageScripts": [],
                    "sourceFile": path == "src/lib.rs", "digest": hashes[path]} for path in sorted(wanted)]
        same(inventory["entries"], entries, "quality frozen inventory differs")
        require(inventory["schemaVersion"] == 1 and inventory["repositoryId"] == case["caseId"]
                and inventory["generation"] == "filesystem:" + digest(encoded(entries))
                and inventory["digest"] == digest(encoded([1, case["caseId"], inventory["generation"], entries])), "quality inventory digest differs")
        selected = [item for item in entries if item["path"] == ("Cargo.toml" if build else "src/lib.rs")]
        denominator = digest(encoded([inventory["digest"], spec["selector"], selected]))
        require(planned["id"] == provider and planned["version"] == spec["providerVersion"]
                and planned["configuration"]["denominatorCount"] == len(selected)
                and planned["configuration"]["denominatorDigest"] == denominator
                and is_digest(case["planDigest"]) and result["provider"] == provider and result["applicable"] is True, "quality frozen provider/denominator differs")
        rule = "legacy.build.warnings" if build else "legacy.lint.clippy"
        same(case["expected"], {"complete": not failed, "findingCount": int(positive), "ruleId": rule,
                              "rawDiagnostic": "E0425" if failed else ("unused_imports" if build else "clippy::eq_op") if positive else None}, "quality expected control differs")
        policy, receipt = case["policyDefinition"], case["executionReceipt"]
        cwd = PurePosixPath(policy["cwd"])
        require(cwd.is_absolute() and ".." not in cwd.parts and cwd.name == "source" and cwd.parent.name == case["caseId"], "quality source root differs")
        run = cwd.parent / "run"
        tool = api["executable"](policy["tool"]["path"], policy["tool"]["digest"], live=False)
        wrapper = api["executable"](policy["wrapper"]["path"], policy["wrapper"]["digest"], live=False)
        require(tool.name == "cargo" and not tool.is_relative_to(cwd.parent.parent)
                and wrapper == PurePosixPath("/usr/bin/sandbox-exec"), "quality host executable differs")
        escaped = str(cwd).replace("\\", "\\\\").replace('"', '\\"')
        text = f'(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath "{escaped}"))\n'
        profile_hash = digest(text.encode()).removeprefix("sha256:")
        profile = run / "sandbox" / ("audit-" + profile_hash + ".sb")
        sandbox_id = "sandbox:macos:" + profile_hash
        same(policy["profile"], {"path": str(profile), "text": text, "digest": digest(text.encode()), "receiptId": sandbox_id}, "quality native sandbox differs")
        args = ["build"] if build else ["clippy", "--all-targets", "--message-format=json", "--", "-D", "warnings"]
        prefix = ["-f", str(profile), "--", str(tool)]
        accepted = [0] if build else [0, 1, 2, 101]
        require(policy["id"] == "legion-real-quality-command-qualification-v1" and policy["version"] == 1
                and policy["provider"] == provider and policy["task"] == ("build" if build else "lint")
                and policy["plan"] == case["planDigest"] and policy["args"] == args and policy["wrappedArgs"] == prefix + args
                and policy["versionArgs"] == prefix + ["--version"] and policy["acceptedExitCodes"] == accepted
                and policy["artifactRequestId"] == "legion-audit/<64 lowercase hex>; one admission only"
                and policy["timeoutMs"] == 120000 and policy["stdoutLimit"] == policy["stderrLimit"] == 8388608
                and policy["sandbox"] == "native-macos-deny-network-quality-command-contract", "quality exact SDK policy differs")
        environment = {"PATH": policy["environment"]["PATH"], "HOME": str(cwd.parent.parent / "home")}
        require(environment["PATH"].split(":")[0] == str(tool.parent), "quality actual toolchain PATH differs")
        for part in environment["PATH"].split(":"):
            path = PurePosixPath(part)
            require(path.is_absolute() and ".." not in path.parts and str(path) == part, "quality retained PATH differs")
        cache = {"TMPDIR": "tmp", "TEMP": "tmp", "TMP": "tmp", "XDG_CACHE_HOME": "cache/xdg", "CARGO_TARGET_DIR": "cache/cargo-target",
                 "npm_config_cache": "cache/npm", "RUFF_CACHE_DIR": "cache/ruff", "MYPY_CACHE_DIR": "cache/mypy", "PYTHONPYCACHEPREFIX": "cache/pycache", "GOCACHE": "cache/go-build"}
        environment.update({key: str(run / value) for key, value in cache.items()})
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONNOUSERSITE"] = "1"
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
        same(policy["environment"], environment, "quality environment differs")
        same(policy["environmentAllowlist"], sorted(set(["PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"] + list(cache) + ["PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "GIT_CONFIG_NOSYSTEM"])), "quality environment allowlist differs")
        same(receipt, result["details"]["executionReceipt"], "quality native receipt differs")
        decisions = case["policyDecisions"]
        require(len(decisions) == 1 and decisions[0]["allowed"] is True, "quality SDK admissions missing/duplicated")
        decision, version = decisions[0], receipt["executable"]["version"]
        require(re.fullmatch(r"legion-audit/[0-9a-f]{64}", receipt["requestId"]) is not None
                and receipt["receiptId"] == "receipt:" + receipt["requestId"] and decision["requestId"] == receipt["requestId"]
                and receipt["providerId"] == decision["providerId"] == provider and receipt["planId"] == decision["planId"] == case["planDigest"]
                and receipt["taskId"] == decision["taskId"] == policy["task"] and receipt["cwd"] == decision["cwd"] == str(cwd)
                and receipt["command"]["args"] == decision["args"] == prefix + args
                and receipt["command"]["executable"] == decision["executable"] == receipt["executable"]["canonicalPath"] == str(wrapper)
                and receipt["executable"]["digest"] == decision["expectedDigest"] == policy["wrapper"]["digest"]
                and receipt["policyId"] == receipt["policy"]["id"] == policy["id"] and receipt["policy"]["allowed"] is True
                and receipt["policy"]["version"] == 1 and receipt["policy"]["digest"] == digest(encoded(policy)), "quality native admission linkage differs")
        require(version["qualified"] is True and version["exitCode"] == 0 and version["output"].startswith("cargo 1.98.0 ")
                and version["args"] == decision["versionArgs"] == prefix + ["--version"]
                and receipt["signal"] is None and all(receipt["processTree"][key] is True for key in ("started", "terminated", "reaped")), "quality process/version evidence incomplete")
        require(decision["requiresNetworkSandbox"] is True and decision["acceptedExitCodes"] == accepted
                and decision["timeoutMs"] == 120000 and decision["stdoutLimit"] == decision["stderrLimit"] == 8388608
                and decision["environmentNames"] == sorted(environment) and decision["environmentDigest"] == digest(encoded(environment)), "quality admitted bounds/environment differ")
        same(decision["sandbox"], {"id": sandbox_id, "network": True, "filesystemScope": str(cwd)}, "quality admitted sandbox differs")
        same(receipt["sandbox"], {"required": True, "receiptId": sandbox_id, "networkEnabled": True}, "quality executed sandbox differs")
        out, err = case["actualStdout"], case["actualStderr"]
        for stream, data in (("stdout", out), ("stderr", err)):
            api["artifact"](receipt[stream], data)
        report = [parsed(line, "retained Cargo JSONL") for line in out.splitlines() if line.strip()] if not build else []
        same(case["actualToolReport"], report, "quality actual tool report differs")
        diagnostics = [item for item in report if item.get("reason") == "compiler-message" and item["message"].get("level") in ("error", "warning")]
        require(result["details"]["candidates"] == [] and len(result["findings"]) == int(positive), "quality native output stage differs")
        if failed:
            require(result["complete"] is False and result["coverage_gaps"] and receipt["exitCode"] == 101
                    and "E0425" in out + err and "missing_name" in out + err, "quality failure control became clean")
            if build:
                require(receipt["state"] == "failed" and receipt["complete"] is False, "failed build receipt became successful")
            else:
                require("cargo-clippy-diagnostic-exit-unproven" in result["coverage_gaps"]
                        and any(item["message"].get("code", {}).get("code") == "E0425" for item in diagnostics), "compiler failure classified as lint")
        else:
            coverage = result["coverage"]
            require(result["complete"] is True and result["status"] in ("ok", "complete") and result["coverage_gaps"] == result["degradation"] == []
                    and coverage["expected"] == coverage["examined"] == len(selected) and coverage["gaps"] == []
                    and coverage["denominator_digest"] == denominator and receipt["state"] == "completed" and receipt["complete"] is True
                    and receipt["gaps"] == [] and receipt["exitCode"] == (101 if positive and not build else 0), "quality successful denominator/process incomplete")
            count = result["details"]["findingsCount"]
            if build:
                require(count == sum(re.search(r"\bwarn(?:ing)?\b", line, re.I) is not None for line in (out + "\n" + err).splitlines()), "build warning line count differs")
                require((count > 0) is positive and (not positive or ("warning: unused import: `std::fmt`" in err and "src/lib.rs:1:5" in err
                        and "generated 1 warning" in err and sum(line.startswith("warning:") for line in err.splitlines()) == 2)), "build raw fixture diagnostic differs")
            else:
                require(report and report[-1] == {"reason": "build-finished", "success": not positive}
                        and count == len(diagnostics) and bool(diagnostics) is positive, "clippy terminal/diagnostic count differs")
                for item in diagnostics:
                    message = item["message"]
                    require(message["level"] == "error" and message["code"]["code"] == "clippy::eq_op"
                            and any(span["is_primary"] is True and span["file_name"] == "src/lib.rs" and span["line_start"] == 2 for span in message["spans"]), "clippy raw fixture diagnostic differs")
            if positive:
                path = selected[0]["path"]
                finding = digest(f"{rule}\0{path}\0{1}".encode())
                same(result["findings"], [{"id": finding, "severity": "medium"}], "quality aggregate finding differs")
                same(result["details"]["findingEvidence"], {finding: {"ruleId": rule, "path": path, "line": 1,
                     "message": f"{'build' if build else 'lint'} reported {count} finding(s)"}}, "quality aggregate evidence differs")
        identities.append((policy["tool"], policy["wrapper"], version["output"]))
    require(all(identity == identities[0] for identity in identities), "quality host tool changed between controls")
    same(bound["fixtureSources"], fixture_sources, "quality corpus binding incomplete")
    require(bound["fixtureSourcesDigest"] == digest(encoded(fixture_sources)), "quality corpus digest differs")
    same(row["metrics"], {"cases": 3, "matched": 3, "mismatched": 0}, "quality metrics differ")


def controls(row, entry):
    if entry["family"] == "runtime-app-sdk":
        require(row["schema"] == "legion-runtime-app-sdk-accuracy/1" and row["provider"] == entry["provider"] == "legacy.runtime.app"
                and row["family"] == "runtime-app-sdk" and row["stage"] == entry["stage"] == "finding"
                and row["scope"] == entry["scope"] == helper("audit-runtime-app-accuracy.py")["SCOPE"]
                and all(row[key] is False for key in ("productionQualification", "wholeProviderQualified", "unmodifiedResolverQualified", "productionAdmissionQualified"))
                and row["qualificationEligible"] is True and row["status"] == "pass"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "runtime app constructed SDK identity/scope differs")
        return
    if entry["family"] == "supply-chain-native":
        require(row["schema"] == "legion-supply-chain-native-accuracy/1" and row["provider"] == entry["provider"] == "supply-chain.license-sbom-provenance"
                and row["family"] == "supply-chain-native" and row["stage"] == entry["stage"] == "candidate"
                and row["scope"] == entry["scope"] == helper("audit-supply-chain-native-accuracy.py")["SCOPE"]
                and row["qualificationEligible"] is row["boundedSbomLicenseKnownAnswerEligible"] is True
                and row["productionQualification"] is row["wholeProviderQualification"] is row["targetBuildProvenanceVerified"] is False
                and row["requiredGap"] == "supply-chain-provenance-invalid" and row["status"] == "pass"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "supply-chain bounded scope/target gap differs")
        return
    if entry["family"] == "quality-test-native":
        require(entry["provider"] == row["provider"] == "legacy.quality.test" and row["family"] == "quality-test-native"
                and row["stage"] == entry["stage"] == "finding"
                and row["claimScope"] == entry["scope"] == helper("audit-quality-test-accuracy.py")["FAMILY_SCOPE"]
                and all(row[key] is False for key in ("productionQualification", "wholeProviderQualified", "auditCleanClaim", "osSandboxQualified")), "native test qualification expanded authority/scope")
        return
    if entry["family"] == "dotnet-sdk":
        require(entry["provider"] == row.get("provider") == "code.dotnet"
                and row.get("schema") == "legion-dotnet-sdk-accuracy/1"
                and row.get("productionQualification") is False
                and row.get("claimScope") == entry["scope"] == "known-answer-fixture-cases"
                and row.get("qualificationEligible") is True and row.get("missingControls") == []
                and row.get("status") == "observed-known-answer-controls"
                and row.get("metrics", {}).get("boundedSdkAccuracyQualified") is True
                and row.get("metrics", {}).get("wholeProviderQualified") is False
                and row.get("executedScope") == ["restore", "build", "analyzer", "test"]
                and type(row.get("modelCalls")) is int and row["modelCalls"] == 0,
                "incomplete/unexecuted .NET SDK controls cannot qualify")
        return
    if entry["family"] == "code-rust-sdk":
        require(row["provider"] == entry["provider"] == "code.rust" and row["qualificationEligible"] is True and row["productionQualification"] is False and row["claimScope"] == entry["scope"] == "known-answer-fixture-cases" and row["metrics"]["wholeProviderQualified"] is False, "Rust bounded claim differs")
        return
    if entry["family"] == "compatibility-report":
        api = helper("validate-compatibility-report-accuracy.py")
        require(row["schema"] == api["SCHEMA"] and row["provider"] == entry["provider"] == "compatibility.core"
                and row["stage"] == entry["stage"] == "fact-output" and row["scope"] == entry["scope"] == api["SCOPE"]
                and row["qualificationEligible"] is True and row["productionQualification"] is False
                and row["wholeProviderQualified"] is False and row["auditCleanClaim"] is False,
                "compatibility report protocol-only scope differs")
        return
    if entry["family"] == "code-mobile-sdk":
        require(row["schema"] == "legion-mobile-sdk-controls/2" and row["provider"] == entry["provider"] == "code.mobile"
                and row["family"] == "code-mobile-sdk" and row["stage"] == entry["stage"] == "finding"
                and row["scope"] == entry["scope"] == helper("audit-mobile-sdk-accuracy.py")["FAMILY_SCOPE"]
                and row["productionQualification"] is row["wholePlatformQualified"] is row["productionOwnerAdmissionQualified"] is False
                and row["qualificationEligible"] is row["boundedMacosKnownAnswerEligible"] is True
                and row["matrixState"] == "complete" and row["status"] == "observed-known-answer-controls"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "dedicated mobile native identity/bounded scope differs")
        return
    if entry["family"] == "code-c-family-sdk":
        helper("audit-c-family-sdk-registration.py")["adapter"](entry)
        require(row["productionQualification"] is False and row["selfProducerQualification"] is False
                and row["qualificationEligible"] is True and row["assertionsPassed"] is True
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "C-family fixture controls differ")
        return
    if entry["family"] == "ownership-native":
        require(row["schema"] == "legion-ownership-native-sdk-controls/2"
                and row["provider"] == entry["provider"] == "governance.capability-ownership"
                and row["stage"] == entry["stage"] == "finding"
                and row["scope"] == entry["scope"] == helper("validate-ownership-native-accuracy.py")["SCOPE"]
                and row["qualificationEligible"] is True and row["productionQualification"] is False
                and row["wholeProviderQualified"] is False and row["auditCleanClaim"] is False,
                "ownership native qualification scope differs")
        return
    if entry["family"] == "javascript-sdk":
        api = helper("audit-javascript-sdk-accuracy.py")
        require(row.get("schema") == "legion-javascript-sdk-accuracy/1"
                and row.get("kind") == "javascript-sdk-known-answer"
                and row.get("provider") == entry["provider"] == "code.javascript"
                and entry["stage"] == "finding"
                and row.get("productionQualification") is False
                and row.get("qualificationEligible") is True
                and row.get("claimScope") == entry["scope"] == api["FAMILY_SCOPE"]
                and row.get("requiredContract") == api["CONTRACT"]
                and row.get("executedScope") == list(api["TASKS"])
                and row.get("metrics") == {"cases": len(api["CONTROLS"]), "matched": len(api["CONTROLS"]), "mismatched": 0,
                                           "wholeProviderQualified": False, "boundedSdkAccuracyQualified": True}
                and type(row.get("modelCalls")) is int and row.get("modelCalls") == 0,
                "javascript SDK qualification narrowed controls or expanded scope")
        return
    if entry["family"] == "backend-source-facts":
        api = helper("audit-backend-source-facts.py")
        require(row["schema"] == api["SCHEMA"] and row["provider"] == entry["provider"] == "framework.backend"
                and row["stage"] == entry["stage"] == "fact-output" and row["scope"] == entry["scope"] == api["SCOPE"]
                and row["qualificationEligible"] is True and row["status"] == "pass" and row["coverageState"] == "scoped-controls-complete"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0 and type(row["runtimeExamined"]) is int and row["runtimeExamined"] == 0
                and all(row[key] is False for key in api["FALSE_CLAIMS"]), "backend bounded source qualification scope differs")
        return
    if entry["family"] == "code-long-tail":
        require(row["schema"] == "legion-code-long-tail-native-accuracy/1"
                and row["provider"] == entry["provider"] == "code.long-tail"
                and row["stage"] == entry["stage"] == "finding"
                and row["scope"] == entry["scope"] == helper("audit-code-long-tail-accuracy.py")["FAMILY_SCOPE"]
                and row["productionQualification"] is False and row["wholeProviderQualified"] is False
                and row["auditCleanClaim"] is False and row["compilerCoverageQualified"] is False
                and row["languageCoverageQualified"] is False and row["qualificationEligible"] is True
                and row["status"] == "pass" and row["coverageState"] == "scoped-controls-complete"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "dedicated generic-source qualification expanded unsupported language coverage")
        return
    if entry["family"] == "code-jvm-sdk":
        api = helper("audit-jvm-sdk-accuracy.py")
        require(entry["provider"] == row.get("provider") == "code.jvm" and row.get("schema") == "legion-jvm-sdk-accuracy/1"
                and row.get("operationContract") == "jvm/v1" and row.get("productionQualification") is False
                and row.get("qualificationEligible") is True and row.get("sourceUnchanged") is True
                and row.get("controls") == list(api["CONTROLS"]) and row.get("originalContract") == api["ORIGINAL"]
                and row.get("scope") == entry["scope"] == api["SCOPE"], "incomplete JVM SDK original contract/controls cannot qualify")
        return
    if entry["family"] == "code-php-ruby-sdk":
        require(entry["provider"] == row.get("provider") == "code.php-ruby"
                and row.get("schema") == "legion-php-ruby-code-command-sdk-accuracy/1"
                and row.get("productionQualification") is False
                and row.get("claimScope") == entry["scope"] == "known-answer-fixture-cases"
                and row.get("qualificationEligible") is True and row.get("missingControls") == []
                and row.get("status") == "observed-known-answer-controls"
                and row.get("metrics", {}).get("boundedSdkAccuracyQualified") is True
                and row.get("metrics", {}).get("wholeProviderQualified") is False
                and type(row.get("modelCalls")) is int and row["modelCalls"] == 0,
                "incomplete/unexecuted PHP/Ruby SDK controls cannot qualify")
        return
    if entry["family"] == "code-python-sdk":
        require(entry["provider"] == row.get("provider") == "code.python"
                and row.get("schema") == "legion-python-code-command-sdk-accuracy/1"
                and row.get("productionQualification") is False
                and row.get("claimScope") == entry["scope"] == "known-answer-fixture-cases"
                and row.get("qualificationEligible") is True and row.get("missingControls") == []
                and row.get("status") == "observed-known-answer-controls"
                and row.get("metrics", {}).get("boundedSdkAccuracyQualified") is True
                and row.get("metrics", {}).get("wholeProviderQualified") is False
                and type(row.get("modelCalls")) is int and row["modelCalls"] == 0,
                "incomplete/unexecuted Python SDK controls cannot qualify")
        return
    if entry["family"] == "code-sdk":
        # Fixed SDK evidence never drops the original tool/language/platform contract.
        require(row.get("schema") == "legion-code-command-sdk-accuracy/1"
                and row.get("provider") == entry["provider"] in CODE_SDK_PROVIDERS
                and row.get("productionQualification") is False
                and row.get("claimScope") == entry["scope"] == "known-answer-fixture-cases",
                "code SDK diagnostic identity/scope differs")
        require(entry["provider"] == "code.go" and row.get("qualificationEligible") is True
                and row.get("status") == "observed-known-answer-controls" and row.get("missingControls") == []
                and row.get("metrics", {}).get("boundedSdkAccuracyQualified") is True
                and row.get("metrics", {}).get("wholeProviderQualified") is False
                and row.get("modelCalls") == 0 and type(row.get("modelCalls")) is int
                and row.get("executedScope") == row.get("requiredContract", {}).get("tools"),
                "partial code SDK tool/language/platform controls cannot qualify whole providers")
        return
    if entry["family"] == "secrets-history":
        require(row["schema"] == "legion-secrets-history-native-qualification/1"
                and row["family"] == "secrets-history" and row["provider"] == entry["provider"] == "secrets.current-history"
                and row["productionQualification"] is False and row["installedCliAdmission"] is False
                and row["claimScope"] == entry["scope"] == "known-answer-fixture-cases"
                and row["stage"] == entry["stage"] == "finding" and row["status"] == "pass"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "secret history fixture record differs")
        return
    if entry["family"] == "cargo-geiger":
        require(row["schema"] == "legion-cargo-geiger-sdk-accuracy/1" and row["provider"] == entry["provider"] == "legacy.security.rust-unsafe"
                and row["stage"] == entry["stage"] == "candidate" and row["scope"] == entry["scope"] == helper("audit-cargo-geiger-accuracy.py")["FAMILY_SCOPE"]
                and row["productionQualification"] is False and row["qualificationEligible"] is True and row["status"] == "pass"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "cargo-geiger constructed native scope differs")
        return
    if entry["family"] == "cargo-deny":
        require(row["schema"] == "legion-cargo-deny-sdk-accuracy/1" and row["provider"] == entry["provider"] == "legacy.security.rust-policy"
                and row["stage"] == entry["stage"] == "candidate" and row["scope"] == entry["scope"] == helper("audit-cargo-deny-accuracy.py")["FAMILY_SCOPE"]
                and row["productionQualification"] is False and row["qualificationEligible"] is True and row["status"] == "pass"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "cargo-deny constructed native scope differs")
        return
    if entry["family"] == "cargo-audit-sdk":
        require(row["schema"] == "legion-cargo-audit-sdk-accuracy/1" and row["provider"] == entry["provider"] == "legacy.security.rust-advisories"
                and row["stage"] == entry["stage"] == "candidate" and row["scope"] == entry["scope"] == helper("audit-cargo-audit-provider-accuracy.py")["FAMILY_SCOPE"]
                and all(row[key] is False for key in ("productionQualification", "selfProducerQualification", "publicHelperQualification"))
                and row["qualificationEligible"] is True and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "cargo-audit constructed SDK scope differs")
        return
    if entry["family"] == "license-checker":
        require(row["schema"] == "legion-license-checker-native-accuracy/1"
                and row["provider"] == entry["provider"] == "legacy.security.js-licenses"
                and row["stage"] == entry["stage"] == "candidate"
                and row["scope"] == entry["scope"] == helper("audit-license-provider-accuracy.py")["FAMILY_SCOPE"]
                and row["productionQualification"] is False and row["qualificationEligible"] is True
                and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "license-checker constructed native scope differs")
        return
    if entry["family"] == "harness-machete":
        require(row["schema"] == "legion-cargo-machete-accuracy/1"
                and row["kind"] == "cargo-machete-provider-constructed"
                and row["provider"] == entry["provider"] == "legacy.quality.rust-unused-deps"
                and entry["stage"] == "finding" and row["claimScope"] == entry["scope"] == "constructed-native-sdk-fixture"
                and row["productionQualification"] is False and row["selfProducerQualification"] is False
                and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "cargo-machete constructed SDK record identity/claim differs")
        return
    if entry["family"] == "pip-audit":
        require(row["schema"] == "legion-pip-audit-sdk-accuracy/1" and row["provider"] == entry["provider"] == "legacy.security.python-dependencies"
                and row["scope"] == entry["scope"] == "exact-listed-online-pins-fixture-controls" and row["stage"] == entry["stage"] == "candidate"
                and row["productionQualification"] is False and row["selfProducerQualification"] is False
                and row["qualificationEligible"] is True and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "pip-audit exact listed pin fixture scope differs")
        return
    if entry["family"] == "semgrep-sdk":
        require(row["schema"] == "legion-semgrep-provider-accuracy/1" and row["provider"] == entry["provider"] == "legacy.security.sast"
                and row["stage"] == entry["stage"] == "candidate" and row["scope"] == entry["scope"] == helper("audit-semgrep-provider-accuracy.py")["FAMILY_SCOPE"]
                and row["productionQualification"] is False and row["qualificationEligible"] is True and row["status"] == "pass"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "Semgrep constructed SDK claim differs")
        return
    if entry["family"] == "harness-rust-outdated":
        require(row["schema"] == "legion-rust-outdated-sdk-accuracy/1"
                and row["kind"] == "rust-outdated-provider-constructed"
                and row["provider"] == entry["provider"] == "legacy.stack.rust-outdated"
                and entry["stage"] == "finding" and row["claimScope"] == entry["scope"] == "constructed-native-sdk-fixture"
                and row["productionQualification"] is False and row["selfProducerQualification"] is False
                and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "rust-outdated constructed SDK record identity/claim differs")
        return
    if entry["family"] == "node-outdated":
        require(row["schema"] == "legion-node-outdated-sdk-accuracy/1" and row["provider"] == entry["provider"] == "legacy.stack.node-outdated"
                and row["stage"] == entry["stage"] == "finding" and row["scope"] == entry["scope"] == helper("audit-node-outdated-accuracy.py")["FAMILY_SCOPE"]
                and row["productionQualification"] is False and row["qualificationEligible"] is True and row["status"] == "pass"
                and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "npm constructed native scope differs")
        return
    if entry["family"] == "osv-artifact":
        require(row["schema"] == "legion-osv-sdk-artifact-accuracy/1"
                and row["provider"] == entry["provider"] == "dependency.osv" and row["stage"] == entry["stage"] == "finding"
                and row["scope"] == entry["scope"] == helper("audit-osv-artifact-accuracy.py")["FAMILY_SCOPE"]
                and all(row[key] is False for key in ("productionQualification", "selfProducerQualification", "publicHelperQualification"))
                and row["qualificationEligible"] is True and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "OSV constructed SDK/artifact scope differs")
        return
    if entry["family"] == "opengrep-artifact":
        require(row["schema"] == "legion-opengrep-sdk-artifact-accuracy/1"
                and row["provider"] == entry["provider"] == "security.opengrep" and row["stage"] == entry["stage"] == "candidate"
                and row["scope"] == entry["scope"] == "constructed-native-sdk-artifact-fixture"
                and row["productionQualification"] is False and row["selfProducerQualification"] is False
                and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "OpenGrep constructed SDK/artifact scope differs")
        return
    if entry["family"] == "harness-ast-grep":
        require(row["schema"] == "legion-ast-grep-accuracy/1"
                and row["providerId"] == entry["provider"] == "structural.ast-grep"
                and row["claimScope"] == entry["scope"] == "constructed-native-sdk-artifact-fixture"
                and row["productionQualification"] is False and row["selfProducerQualification"] is False,
                "ast-grep SDK record identity/claim differs")
        return
    if entry["family"] == "harness-quality":
        require(row["schema"] == "legion-quality-command-sdk-accuracy/1"
                and row["kind"] == "quality-command-sdk-constructed" and row["productionQualification"] is False
                and row["claimScope"] == entry["scope"] == "known-answer-fixture-cases"
                and row["provider"] == entry["provider"] and entry["stage"] == "finding"
                and row["status"] == "pass" and type(row["modelCalls"]) is int and row["modelCalls"] == 0,
                "quality SDK record identity/claim differs")
        return
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
            "validationBasis": "native-family-validator",
            "stage": entry["stage"], "scope": entry["scope"]}
    if entry["family"] == "reasoning-runtime":
        value.update(helper("audit-reasoning-runtime-registration.py")["qualification_fields"]())
    if entry["family"] == "runtime-app-sdk":
        value.update({"productionQualification": False, "wholeProviderQualified": False,
                      "unmodifiedResolverQualified": False, "productionAdmissionQualified": False,
                      "fixtureScope": entry["scope"], "admissionScope": "explicit attested fixture executable mapping only"})
    if entry["family"] == "supply-chain-native":
        value.update({"productionQualification": False, "wholeProviderQualification": False, "targetBuildProvenanceVerified": False,
                      "auditCleanClaim": False, "fixtureScope": entry["scope"], "requiredTargetGap": "supply-chain-provenance-invalid",
                      "admissionScope": "constructed exact SDK authorizer; production owner admission remains denied",
                      "coverageScope": "full constructed npm-v3 dev/transitive dual SBOM/license controls; target build provenance unproven"})
    if entry["family"] == "code-rust-sdk":
        value.update({"productionQualification": False, "selfProducerQualification": False, "publicHelperQualification": False, "wholeProviderQualified": False, "fixtureScope": entry["scope"], "admissionScope": "exact constructed SDK fixture authorizer; production owner admission remains denied", "coverageScope": "five original Rust tasks; features/targets & unsafe soundness remain explicit gaps; unchanged historical RustSec subset only"})
    if entry["family"] == "compatibility-report":
        value.update({"productionQualification": False, "wholeProviderQualified": False, "auditCleanClaim": False,
                      "certificationClaim": False, "fixtureScope": entry["scope"],
                      "coverageScope": "v1-core fields only; excludes v2-only fields & extensions",
                      "admissionScope": "package report-protocol observation only; runtime evidence trust remains unavailable"})
    if entry["family"] == "code-mobile-sdk":
        value.update({"productionQualification":False, "wholePlatformQualified":False, "productionOwnerAdmissionQualified":False,
                      "fixtureScope":entry["scope"], "admissionScope":"constructed exact SDK admission; production owner admission remains denied",
                      "coverageScope":"macOS SwiftPM Swift/Objective-C/Objective-C++ Foundation/XCTest compiler/analyzer/test; explicit unsupported platform/framework gaps remain"})
    if entry["family"] == "ownership-native":
        value.update({"productionQualification": False, "wholeProviderQualified": False, "auditCleanClaim": False,
                      "fixtureScope": entry["scope"], "admissionScope": "constructed exact SDK authorizer; actual Scanner production trust required"})
    if entry["family"] == "code-c-family-sdk":
        value.update(helper("audit-c-family-sdk-registration.py")["qualification_fields"]())
    if entry["family"] == "backend-source-facts":
        value.update({"productionQualification": False, "wholeProviderQualified": False, "auditCleanClaim": False,
                      "runtimeQualified": False, "authQualified": False, "certificationClaim": False, "runtimeExamined": 0,
                      "fixtureScope": entry["scope"], "coverageScope": "exact thirteen named literal source facts only; runtime, mount composition & auth remain unproven"})
    if entry["family"] == "quality-test-native":
        value.update({"productionQualification":False,"wholeProviderQualified":False,"auditCleanClaim":False,"osSandboxQualified":False,
                      "fixtureScope":entry["scope"],"admissionScope":"explicit constructed SDK authorizer; production owner admission remains unavailable",
                      "cleanupScope":"authenticated terminal jobs removed; uncertain timeout/cancel copies retained"})
    if entry["family"] == "code-long-tail":
        value.update({"productionQualification": False, "wholeProviderQualified": False,
                      "auditCleanClaim": False, "compilerCoverageQualified": False,
                      "languageCoverageQualified": False, "fixtureScope": entry["scope"],
                      "coverageScope": "bounded generic source rules only; mandatory missing-language-provider gaps remain"})
    if entry["family"] == "cargo-geiger":
        value.update({"productionQualification": False, "fixtureScope": entry["scope"],
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] == "cargo-deny":
        value.update({"productionQualification": False, "fixtureScope": entry["scope"],
                      "databaseScope": "official-advisory-subset fixture; no full/current RustSec database or advisory-detection claim",
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] == "pip-audit":
        value.update({"productionQualification": False, "selfProducerQualification": False,
                      "fixtureScope": "exact-listed-online-pins-fixture-controls",
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim",
                      "advisoryDatabase": "mutable online PyPI responses; no immutable database identity claim"})
    if entry["family"] == "node-outdated":
        value.update({"productionQualification": False, "fixtureScope": entry["scope"],
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] == "bench-known-answer":
        value.update({"benchClass": BENCH[entry["provider"]], "productionQualification": False})
    if entry["family"] == "secrets-history":
        value.update({"productionQualification": False, "installedCliAdmission": False, "fixtureScope": "known-answer-fixture-cases",
                      "admissionScope": "explicit constructed SDK authorizer; sandbox disabled in synthetic fixture only"})
    if entry["family"] == "cargo-audit-sdk":
        value.update({"productionQualification": False, "selfProducerQualification": False, "publicHelperQualification": False,
                      "fixtureScope": entry["scope"]})
    if entry["family"] == "license-checker":
        value.update({"productionQualification": False, "fixtureScope": entry["scope"],
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] in ("harness-machete", "harness-rust-outdated"):
        value.update({"productionQualification": False, "selfProducerQualification": False,
                      "fixtureScope": "constructed-native-sdk-fixture",
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] == "javascript-sdk":
        value.update({"productionQualification": False, "wholeProviderQualified": False,
                      "fixtureScope": entry["scope"], "packageManagerScope": "explicit pinned pnpm fixture controls",
                      "admissionScope": "exact fixture SDK authorizer; production default owner admission denied"})
    if entry["family"] == "code-jvm-sdk":
        value.update({"productionQualification": False, "fixtureScope": entry["scope"], "operationContract": "jvm/v1", "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] in ("dotnet-sdk", "code-sdk", "code-python-sdk", "code-php-ruby-sdk"):
        value.update({"productionQualification": False, "fixtureScope": "known-answer-fixture-cases",
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] == "harness-quality":
        value.update({"productionQualification": False, "fixtureScope": "known-answer-fixture-cases",
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] == "osv-artifact":
        value.update({"productionQualification": False, "selfProducerQualification": False, "publicHelperQualification": False,
                      "fixtureScope": entry["scope"]})
    if entry["family"] == "semgrep-sdk":
        value.update({"productionQualification": False, "fixtureScope": entry["scope"],
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] == "opengrep-artifact":
        value.update({"productionQualification": False, "selfProducerQualification": False,
                      "fixtureScope": "constructed-native-sdk-artifact-fixture"})
    if entry["family"] == "harness-ast-grep":
        value.update({"productionQualification": False, "fixtureScope": "constructed-native-sdk-artifact-fixture",
                      "selfProducerQualification": False,
                      "admissionScope": "explicit constructed SDK authorizer; no production CLI owner-admission claim"})
    if entry["family"] == "osv-artifact":
        value.update({"productionQualification": False, "selfProducerQualification": False, "publicHelperQualification": False,
                      "fixtureScope": entry["scope"]})
    return value


def code_mobile_evidence(root, entry, row):
    """Retain original preparation/full observed snapshots, never trusted hashes."""
    refs = entry["codeMobileEvidence"]
    keys(refs, CODE_MOBILE_EVIDENCE)
    directory = f"{ARCHIVE}/records/code.mobile/evidence/{row['qualificationDigest'].removeprefix('sha256:')}/"
    original = {"nativeBefore":row["nativeEnrollment"]["observedBefore"], "nativeAfter":row["nativeEnrollment"]["observedAfter"], "sourceEnrollment":row["sourceEnrollment"]}
    retained, evidence = set(), {}
    for key, filename in CODE_MOBILE_EVIDENCE.items():
        ref = refs[key]
        require(ref.get("path") == directory + filename, "mobile SDK retained native/source layout differs")
        path = reference(root, ref, "records")
        raw = path.read_bytes()
        require(digest(raw) == original[key]["digest"], "original mobile native/source snapshot bytes differ")
        retained.add(ref["path"])
        evidence[original[key]["path"]] = raw
    return retained, evidence


def javascript_sdk_evidence(root, entry, row):
    refs = entry["javascriptSdkEvidence"]
    keys(refs, JAVASCRIPT_SDK_EVIDENCE)
    directory = f"{ARCHIVE}/records/code.javascript/evidence/{row['qualificationDigest'].removeprefix('sha256:')}/"
    retained = set()
    for key, filename in JAVASCRIPT_SDK_EVIDENCE.items():
        require(refs[key].get("path") == directory + filename, "javascript SDK retained evidence layout differs")
        reference(root, refs[key], "records")
        retained.add(refs[key]["path"])
    require(refs["providerRecord"]["sha256"] == entry["record"]["sha256"], "javascript original record bytes differ")
    return retained


def quality_test_evidence(root, entry, row):
    api = helper("audit-quality-test-accuracy.py")
    refs = entry["qualityTestEvidence"]
    names = api["required_evidence_files"](row)
    keys(refs, names)
    directory = f"{ARCHIVE}/records/{entry['provider']}/evidence/{row['qualificationDigest'].removeprefix('sha256:')}/"
    retained = set()
    for name in names:
        ref = refs[name]
        require(ref["path"] == directory + name, "native test retained artifact identity differs")
        path = reference(root, ref, "records")
        retained.add(path.relative_to(root).as_posix())
    return retained


def code_sdk_evidence(root, entry, row):
    """Fixed code-family metadata references; never an arbitrary file escape."""
    refs = entry["codeSdkEvidence"]
    keys(refs, set(CODE_SDK_EVIDENCE) | {"providerRecords"})
    directory = f"{ARCHIVE}/records/{entry['provider']}/evidence/{row['qualificationDigest'].removeprefix('sha256:')}/"
    paths = {}
    for key, filename in CODE_SDK_EVIDENCE.items():
        ref = refs[key]
        require(ref.get("path") == directory + filename, "code SDK retained metadata layout differs")
        paths[key] = reference(root, ref, "records")
    keys(refs["providerRecords"], CODE_SDK_PROVIDERS)
    paths["providerRecords"] = {}
    retained = {refs[key]["path"] for key in CODE_SDK_EVIDENCE}
    for provider, ref in refs["providerRecords"].items():
        require(ref.get("path") == directory + provider.replace(".", "_") + ".json", "code SDK original record layout differs")
        paths["providerRecords"][provider] = reference(root, ref, "records")
        retained.add(ref["path"])
    helper("audit-code-sdk-accuracy.py")["validate_retained"](root, row, paths)
    return retained


def jvm_sdk_evidence(root, entry, row):
    api = helper("audit-jvm-sdk-accuracy.py")
    refs = entry["jvmSdkEvidence"]
    keys(refs, api["retained_files"](row))
    directory = f"{ARCHIVE}/records/code.jvm/evidence/{row['qualificationDigest'].removeprefix('sha256:')}/"
    for filename, ref in refs.items():
        require(ref.get("path") == directory + filename, "JVM SDK original retained layout differs")
        reference(root, ref, "records")
    require(refs["code_jvm.json"]["sha256"] == entry["record"]["sha256"], "JVM original record differs")
    return {ref["path"] for ref in refs.values()}


def php_ruby_sdk_evidence(root, entry, row):
    refs = entry["phpRubySdkEvidence"]
    keys(refs, PHP_RUBY_SDK_EVIDENCE)
    directory = f"{ARCHIVE}/records/code.php-ruby/evidence/{row['qualificationDigest'].removeprefix('sha256:')}/"
    paths = {}
    for key, filename in PHP_RUBY_SDK_EVIDENCE.items():
        require(refs[key].get("path") == directory + filename, "PHP/Ruby SDK original retained layout differs")
        paths[key] = reference(root, refs[key], "records")
    helper("audit-php-ruby-code-sdk-accuracy.py")["validate_retained"](root, row, paths)
    return {ref["path"] for ref in refs.values()}



def python_sdk_evidence(root, entry, row):
    refs = entry["pythonSdkEvidence"]
    keys(refs, PYTHON_SDK_EVIDENCE)
    directory = f"{ARCHIVE}/records/code.python/evidence/{row['qualificationDigest'].removeprefix('sha256:')}/"
    paths = {}
    for key, filename in PYTHON_SDK_EVIDENCE.items():
        require(refs[key].get("path") == directory + filename, "Python SDK original retained layout differs")
        paths[key] = reference(root, refs[key], "records")
    helper("audit-python-code-sdk-accuracy.py")["validate_retained"](root, row, paths)
    return {ref["path"] for ref in refs.values()}


def dotnet_sdk_evidence(root, entry, row):
    refs = entry["dotnetSdkEvidence"]
    keys(refs, DOTNET_SDK_EVIDENCE)
    directory = f"{ARCHIVE}/records/code.dotnet/evidence/{row['qualificationDigest'].removeprefix('sha256:')}/"
    paths = {}
    for key, filename in DOTNET_SDK_EVIDENCE.items():
        require(refs[key].get("path") == directory + filename, ".NET SDK original retained layout differs")
        paths[key] = reference(root, refs[key], "records")
    helper("audit-dotnet-sdk-accuracy.py")["validate_retained"](root, row, paths)
    return {ref["path"] for ref in refs.values()}


def rust_sdk_evidence(root, entry, row):
    refs = entry["rustSdkEvidence"]
    api = helper("audit-rust-code-sdk-accuracy.py")
    keys(refs, api["retained_files"](row))
    directory = f"{ARCHIVE}/records/code.rust/evidence/{row['qualificationDigest'].removeprefix('sha256:')}/"
    for filename, ref in refs.items():
        require(ref.get("path") == directory + filename, "Rust SDK original retained layout differs")
        reference(root, ref, "records")
    require(refs["code_rust.json"]["sha256"] == entry["record"]["sha256"], "Rust original record differs")
    return {ref["path"] for ref in refs.values()}


def runtime_app_evidence(root, entry, row):
    """Rebind source-declared raw artifacts beneath this original record digest."""
    api = helper("audit-runtime-app-accuracy.py")
    directory = str(PurePosixPath(entry["record"]["path"]).parent / "evidence" / row["qualificationDigest"].removeprefix("sha256:"))
    paths = {directory + "/" + relative for relative in api["retained_files"](row)}
    require(bool(paths), "runtime app retained native evidence missing")
    for relative in paths:
        relative_file(root, relative)
    api["validate_record"](root, row, live=False, retained=root / directory)
    return paths


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
        keys(entry, ENTRY_KEYS | {"backendSourceEvidence"} if entry.get("family") == "backend-source-facts" else ENTRY_KEYS | {"phpRubySdkEvidence"} if entry.get("family") == "code-php-ruby-sdk" else ENTRY_KEYS | {"qualityTestEvidence"} if entry.get("family") == "quality-test-native" else ENTRY_KEYS | {"rustSdkEvidence"} if entry.get("family") == "code-rust-sdk" else ENTRY_KEYS | {"dotnetSdkEvidence"} if entry.get("family") == "dotnet-sdk" else ENTRY_KEYS | {"javascriptSdkEvidence"} if entry.get("family") == "javascript-sdk" else ENTRY_KEYS | {"codeMobileEvidence"} if entry.get("family") == "code-mobile-sdk" else ENTRY_KEYS | {"jvmSdkEvidence"} if entry.get("family") == "code-jvm-sdk" else ENTRY_KEYS | {"pythonSdkEvidence"} if entry.get("family") == "code-python-sdk" else ENTRY_KEYS | {"codeSdkEvidence"} if entry.get("family") == "code-sdk" else ENTRY_KEYS)
        require(entry["provider"] in specs and entry["provider"] not in entries, "unexpected/duplicate index provider")
        entries[entry["provider"]] = entry
    retained = {INDEX, SCHEMA}
    for provider, entry in entries.items():
        require(entry["stage"] in ("candidate", "finding", "fact-output", "outcome") and isinstance(entry["scope"], str) and 0 < len(entry["scope"]) <= 1000, "missing corpus claim/stage")
        source_closure(root, entry)
        path = reference(root, entry["record"], "records", original=True)
        require(path.parent.name == provider, "record directory must name provider")
        raw_record = path.read_bytes() if entry["family"] == "semgrep-sdk" else None
        row = parsed(raw_record, path) if raw_record is not None else load(path)
        _, _, mode, _ = adapter(root, entry)
        require(entry["record"]["encoding"] == mode, "original digest encoding differs")
        if entry["family"] == "harness-ast-grep":
            require("qualificationDigest" not in row, "ast-grep receipt must not invent a digest field")
            require(entry["record"]["qualificationDigest"] == digest(encoded(row, mode)), "ast-grep canonical receipt digest changed")
        elif entry["family"] == "semgrep-sdk":
            claimed = row.get("qualificationDigest")
            require(claimed == entry["record"]["qualificationDigest"], "original Semgrep qualification digest differs")
            validate_semgrep_record_digest(raw_record, entry["record"]["qualificationDigest"])
        else:
            claimed = row.pop("qualificationDigest")
            require(claimed == entry["record"]["qualificationDigest"] == digest(encoded(row, mode)), "original qualification digest changed")
            row["qualificationDigest"] = claimed
        if entry["family"] == "reasoning-runtime":
            retained.update(helper("audit-reasoning-runtime-registration.py")["validate"](root, entry, row))
            retained.add(entry["record"]["path"])
            benchmark = specs[provider]["benchmark"]
            require(benchmark["status"] == "qualified", "indexed reasoning provider not registered")
            same(benchmark["qualification"], qualification(entry), "reasoning registry qualification differs")
            require(benchmark["qualificationDigest"] == digest(encoded(benchmark["qualification"])), "reasoning registry qualification digest differs")
            continue
        if entry["family"] == "backend-source-facts":
            retained.update(backend_source_evidence(root, entry, row)[0])
        if entry["family"] == "runtime-app-sdk":
            retained.update(runtime_app_evidence(root, entry, row))
        if entry["family"] == "javascript-sdk":
            retained.update(javascript_sdk_evidence(root, entry, row))
        if entry["family"] == "code-rust-sdk":
            retained.update(rust_sdk_evidence(root, entry, row))
        if entry["family"] == "code-jvm-sdk":
            retained.update(jvm_sdk_evidence(root, entry, row))
        if entry["family"] == "code-php-ruby-sdk":
            retained.update(php_ruby_sdk_evidence(root, entry, row))
        if entry["family"] == "code-mobile-sdk":
            retained.update(code_mobile_evidence(root, entry, row)[0])
        if entry["family"] == "quality-test-native":
            retained.update(quality_test_evidence(root, entry, row))
        if entry["family"] == "dotnet-sdk":
            retained.update(dotnet_sdk_evidence(root, entry, row))
        if entry["family"] == "code-python-sdk":
            retained.update(python_sdk_evidence(root, entry, row))
        if entry["family"] == "code-sdk":
            retained.update(code_sdk_evidence(root, entry, row))
        controls(row, entry)
        require(row.get("claimScope") == entry["scope"] if entry["family"] in ("code-php-ruby-sdk", "quality-test-native", "dotnet-sdk", "code-rust-sdk", "javascript-sdk", "code-c-family-sdk", "code-python-sdk", "code-sdk", "bench-known-answer", "harness-quality", "harness-ast-grep", "harness-machete", "secrets-history", "harness-rust-outdated") else row["scope"] == entry["scope"], "corpus claim differs from original")
        validated = record_binding(root, entry, path, row, specs, raw_record=raw_record)
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
