"""Dedicated .NET registration boundaries; these units grant no qualification."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
gate = runpy.run_path(str(ROOT / "scripts/ci/audit-qualification-records.py"))
validator = runpy.run_path(str(ROOT / "scripts/ci/audit-dotnet-sdk-accuracy.py"))
provisioner = runpy.run_path(str(ROOT / "scripts/ci/provision-dotnet-qualification-tools.py"))


class DotnetPackageHashTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", "/Volumes/D/scratch"))
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.packages = self.root / "packages"
        self.cache = self.packages / "example.package/1.0.0"
        self.cache.mkdir(parents=True)
        self.filename = "example.package.1.0.0.nupkg"
        # Synthetic bytes exercise hash domains only; no signed-package claim.
        self.archive = b"archive including signature bytes"
        self.archive_hash = base64.b64encode(hashlib.sha512(self.archive).digest()).decode()
        self.content_hash = base64.b64encode(hashlib.sha512(b"unsigned content").digest()).decode()
        self.row = {"type": "Direct", "resolved": "1.0.0", "contentHash": self.content_hash}
        self.lock = self.root / "packages.lock.json"
        self.lock.write_text(json.dumps({"version": 1, "dependencies": {"net8.0": {"Example.Package": self.row}}}))
        (self.cache / self.filename).write_bytes(self.archive)
        (self.cache / (self.filename + ".sha512")).write_text(self.archive_hash + "\n")
        (self.cache / ".nupkg.metadata").write_text(json.dumps({"version": 2, "contentHash": self.content_hash, "source": "https://api.nuget.org/v3/index.json"}))
        self.failure = self.root / "code-dotnet-sdk/provisioning-failure"

    def provision(self):
        return provisioner["package_provenance"](self.lock, "Example.Package", self.row, self.packages, self.failure)

    def test_distinct_archive_and_content_hashes_remain_separate_in_provenance(self):
        result = self.provision()
        self.assertNotEqual(self.archive_hash, self.content_hash)
        self.assertEqual(result["archiveSha512"], self.archive_hash)
        self.assertEqual(result["contentHash"], self.content_hash)
        self.assertEqual(result["url"], "https://api.nuget.org/v3-flatcontainer/example.package/1.0.0/" + self.filename)
        self.assertFalse(self.failure.exists())

    def test_archive_mismatch_retains_exact_originals_and_both_comparisons(self):
        (self.cache / self.filename).write_bytes(self.archive + b"changed")
        with self.assertRaises(ValueError):
            self.provision()
        for filename in (self.filename, self.filename + ".sha512", ".nupkg.metadata"):
            self.assertEqual((self.failure / filename).read_bytes(), (self.cache / filename).read_bytes())
        self.assertEqual((self.failure / "packages.lock.json").read_bytes(), self.lock.read_bytes())
        report = json.loads((self.failure / "comparison.json").read_bytes())
        self.assertEqual((report["id"], report["version"]), ("Example.Package", "1.0.0"))
        self.assertFalse(report["archiveMatchesSidecar"])
        self.assertTrue(report["metadataMatchesLock"])
        self.assertEqual(report["archiveSha512"], base64.b64encode(hashlib.sha512(self.archive + b"changed").digest()).decode())

    def test_metadata_lock_mismatch_cannot_fall_back_to_archive_hash(self):
        (self.cache / ".nupkg.metadata").write_text(json.dumps({"contentHash": self.archive_hash}))
        with self.assertRaises(ValueError):
            self.provision()
        report = json.loads((self.failure / "comparison.json").read_bytes())
        self.assertTrue(report["archiveMatchesSidecar"])
        self.assertFalse(report["metadataMatchesLock"])
        self.assertEqual(report["lockContentHash"], self.content_hash)
        self.assertEqual(report["metadataContentHash"], self.archive_hash)

    def test_missing_metadata_retains_available_inputs_and_error(self):
        (self.cache / ".nupkg.metadata").unlink()
        with self.assertRaises(ValueError):
            self.provision()
        report = json.loads((self.failure / "comparison.json").read_bytes())
        self.assertIn(".nupkg.metadata", report["inputErrors"])
        self.assertFalse(report["metadataMatchesLock"])
        self.assertEqual((self.failure / self.filename).read_bytes(), self.archive)

    def test_malformed_metadata_fails_closed(self):
        (self.cache / ".nupkg.metadata").write_bytes(b"{malformed metadata")
        with self.assertRaises(ValueError):
            self.provision()
        self.assertEqual((self.failure / ".nupkg.metadata").read_bytes(), b"{malformed metadata")

    def test_first_failure_evidence_cannot_be_overwritten(self):
        (self.cache / (self.filename + ".sha512")).write_text(self.content_hash)
        with self.assertRaises(ValueError):
            self.provision()
        original = (self.failure / "comparison.json").read_bytes()
        (self.cache / self.filename).write_bytes(b"later corruption")
        with self.assertRaises(FileExistsError):
            self.provision()
        self.assertEqual((self.failure / "comparison.json").read_bytes(), original)


class DotnetSdkAdapterTests(unittest.TestCase):
    def environment_request(self, scratch, enrollment, language, task):
        control = scratch / "cache/dotnet-control"
        environment = {
            "PATH": enrollment["sdkRoot"], "NO_COLOR": "1", "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never", "DOTNET_ROOT": enrollment["sdkRoot"],
            "DOTNET_MULTILEVEL_LOOKUP": "0", "DOTNET_ROLL_FORWARD": "LatestPatch",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
            "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true", "DOTNET_NOLOGO": "1",
            "MSBUILDDISABLENODEREUSE": "1", "MSBuildEnableWorkloadResolver": "false",
            "NUGET_PACKAGES": enrollment["packagesRoot"],
            "NUGET_HTTP_CACHE_PATH": str(control / "http-cache"),
            "DOTNET_CLI_HOME": str(control / "home"),
            "LEGION_DOTNET_INPUT_MANIFEST": str(control / "inputs.json"),
            "LEGION_DOTNET_FRAMEWORKS": "net8.0",
            "LEGION_DOTNET_TEST_RESULTS": str(control / "test-results-0"),
            "HOME": str(control / "home"), "USERPROFILE": str(control / "home"),
            "XDG_CONFIG_HOME": str(control / "home/.config"),
            "MSBuildUserExtensionsPath": str(control / "home/msbuild"),
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1",
        }
        for name, path in (("TMPDIR", "tmp"), ("TEMP", "tmp"), ("TMP", "tmp"),
                           ("XDG_CACHE_HOME", "cache/xdg"), ("CARGO_TARGET_DIR", "cache/cargo-target"),
                           ("npm_config_cache", "cache/npm"), ("RUFF_CACHE_DIR", "cache/ruff"),
                           ("MYPY_CACHE_DIR", "cache/mypy"), ("PYTHONPYCACHEPREFIX", "cache/pycache"),
                           ("GOCACHE", "cache/go-build")):
            environment[name] = str(scratch / path)
        if language == "fsharp" and task == "analyzer":
            environment["LEGION_DOTNET_FSHARP_FILES"] = '["fsharp/Answer.fs","fsharp/Tests.fs"]'
        if task == "test":
            environment["DOTNET_SYSTEM_NET_DISABLEIPV6"] = "1"
        allowed = set(environment) | {"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"}
        return {"environment": environment, "environmentAllowlist": sorted(allowed)}

    def test_ipv6_override_is_exact_and_test_only(self):
        scratch = PurePosixPath("/native/scratch")
        enrollment = {"sdkRoot": "/sdk", "packagesRoot": "/sdk/packages"}
        name = "DOTNET_SYSTEM_NET_DISABLEIPV6"
        for language in ("csharp", "fsharp", "visualBasic"):
            for task in validator["TASKS"]:
                request = self.environment_request(scratch, enrollment, language, task)
                validator["environment"](request, scratch, enrollment, language, task)
                if task == "test":
                    for value in (None, "0", "true", 1):
                        changed = copy.deepcopy(request)
                        if value is None:
                            changed["environment"].pop(name)
                        else:
                            changed["environment"][name] = value
                        with self.subTest(language=language, value=value), self.assertRaisesRegex(AssertionError, "SDK environment differs"):
                            validator["environment"](changed, scratch, enrollment, language, task)
                    changed = copy.deepcopy(request)
                    changed["environmentAllowlist"].remove(name)
                    with self.subTest(language=language, field="allowlist"), self.assertRaisesRegex(AssertionError, "SDK environment allowlist differs"):
                        validator["environment"](changed, scratch, enrollment, language, task)
                else:
                    changed = copy.deepcopy(request)
                    changed["environment"][name] = "1"
                    changed["environmentAllowlist"] = sorted(set(changed["environmentAllowlist"]) | {name})
                    with self.subTest(language=language, task=task), self.assertRaisesRegex(AssertionError, "unbound environment name"):
                        validator["environment"](changed, scratch, enrollment, language, task)

    def test_vstest_diagnostics_bind_exact_case_control_path_for_test_only(self):
        scratch = PurePosixPath("/native/qualification case")
        enrollment = {"packagesRoot": "/sdk/packages",
                      "fsharpAnalyzer": {"root": "/sdk/fsharplint"}}
        for language in ("csharp", "fsharp", "visualBasic"):
            for task in validator["TASKS"]:
                args = validator["commands"](language, task, scratch, enrollment)
                with self.subTest(language=language, task=task):
                    if task == "test":
                        self.assertEqual(args[-2:], ["--diag", "/native/qualification case/cache/dotnet-control/vstest.log"])
                        self.assertEqual(args.count("--diag"), 1)
                    else:
                        self.assertNotIn("--diag", args)

    def sandbox_policy(self):
        # Retained SDK records use macOS POSIX paths even when parsed on Windows.
        scratch = PurePosixPath("/native/scratch")
        stage = scratch / "cache/dotnet-source"
        profiles = validator["qualification_profiles"](stage)
        requests = []
        for task in validator["TASKS"]:
            hashed = validator["digest"](profiles[task].encode()).removeprefix("sha256:")
            prefix = ["-f", str(scratch / "sandbox" / ("audit-" + hashed + ".sb")), "--"]
            requests.append({"taskId": task, "args": prefix + ["/sdk/dotnet", task],
                             "versionArgs": prefix + ["/sdk/dotnet", "--version"],
                             "sandbox": {"id": "sandbox:macos:" + hashed, "network": True,
                                         "filesystemScope": str(stage)}})
        return stage, {"scratch": str(scratch), "profiles": profiles, "requests": requests,
                       "wrapper": "/usr/bin/sandbox-exec", "productionAdmission": False}

    def test_qualification_policy_rejects_udp_nonloopback_and_non_test_expansion(self):
        stage, original = self.sandbox_policy()
        validator["sandbox_policy"](original, stage)
        for task, old, new in (("test", "SOCK_STREAM", "SOCK_DGRAM"),
                               ("test", "localhost:*", "*:*") ,
                               ("test", "localhost:*", "192.0.2.1:*"),
                               ("restore", "(deny network*)", "(allow network*)"),
                               ("build", "(deny network*)", "(allow network*)"),
                               ("analyzer", "(deny network*)", "(allow network*)")):
            changed = copy.deepcopy(original)
            changed["profiles"][task] = changed["profiles"][task].replace(old, new)
            with self.subTest(task=task, replacement=new), self.assertRaisesRegex(AssertionError, "sandbox task profiles differ"):
                validator["sandbox_policy"](changed, stage)

    def test_qualification_policy_rejects_profile_hash_rebinding(self):
        stage, original = self.sandbox_policy()
        validator["sandbox_policy"](original, stage)
        for field in ("args", "versionArgs", "sandbox"):
            changed = copy.deepcopy(original)
            request = changed["requests"][-1]
            if field == "sandbox":
                request[field]["id"] = "sandbox:macos:" + "0" * 64
            else:
                request[field][1] = "/native/scratch/sandbox/audit-" + "0" * 64 + ".sb"
            message = {"args": "sandbox command profile hash differs", "versionArgs": "sandbox version profile hash differs",
                       "sandbox": "sandbox receipt profile hash differs"}[field]
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, message):
                validator["sandbox_policy"](changed, stage)

    def test_retained_path_parser_accepts_only_canonical_posix_absolute_strings(self):
        for value in ("/", "/native/scratch", "/native/scratch space", "/native/évidence"):
            with self.subTest(value=value):
                self.assertEqual(validator["absolute"](value), PurePosixPath(value))
        invalid = ("", "native/scratch", "./native/scratch", "../native/scratch",
                   "/native/../scratch", "/native/./scratch", "/native//scratch", "/native/scratch/",
                   str(PureWindowsPath("/native/scratch")), str(PureWindowsPath("C:/native/scratch")),
                   "C:/native/scratch", str(PureWindowsPath("//server/share/scratch")), "//server/share/scratch",
                   "/native\\scratch", "/native/\0scratch", "/native/\nscratch", "/native/\rscratch",
                   PurePosixPath("/native/scratch"), PureWindowsPath("C:/native/scratch"))
        for value in invalid:
            with self.subTest(value=repr(value)), self.assertRaises(AssertionError):
                validator["absolute"](value)

    def test_policy_rejects_host_native_reinterpretation_of_retained_paths(self):
        stage, original = self.sandbox_policy()
        validator["sandbox_policy"](original, stage)
        for field in ("scratch", "args", "versionArgs", "filesystemScope"):
            changed = copy.deepcopy(original)
            if field == "scratch":
                changed[field] = str(PureWindowsPath(changed[field]))
            elif field == "filesystemScope":
                changed["requests"][-1]["sandbox"][field] = str(PureWindowsPath(stage))
            else:
                changed["requests"][-1][field][1] = str(PureWindowsPath(changed["requests"][-1][field][1]))
            message = {"scratch": "invalid absolute path", "args": "sandbox command profile hash differs",
                       "versionArgs": "sandbox version profile hash differs",
                       "filesystemScope": "sandbox receipt profile hash differs"}[field]
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, message):
                validator["sandbox_policy"](changed, stage)

    def test_approval_and_confinement_scope_are_digest_bound_and_exact(self):
        original = validator["sandbox_admission"]()
        self.assertIn("VSTest harness process tree", original["approval"])
        self.assertFalse(original["inheritedDescriptorConfinementProven"])
        for field, value in (("approval", "approved"), ("task", "build"),
                             ("udp", True), ("productionAdmission", True),
                             ("inheritedDescriptorConfinementProven", True)):
            changed = dict(original, **{field: value})
            with self.subTest(field=field), self.assertRaises(AssertionError):
                validator["validate"](ROOT, {"sandboxAdmission": changed})

    def shared_record(self):
        # Hand-built stand-in for the harness's compaction: a repeated large value, and a stored
        # value that itself references another stored value (children are shared first).
        digest, encoded = validator["digest"], validator["encoded"]
        leaf = {"listing": {"path/a": "sha256:" + "a" * 64}, "tag": "leaf"}
        leaf_key = digest(encoded(leaf))
        parent = {"keep": {"$sharedRef": leaf_key}, "tag": "parent"}
        parent_key = digest(encoded(parent))
        cases = [{"id": 1, "before": {"$sharedRef": parent_key}, "after": {"$sharedRef": parent_key}, "inline": {"tag": "own"}},
                 {"id": 2, "snapshots": [{"$sharedRef": leaf_key}, {"$sharedRef": parent_key}]}]
        expanded = [{"id": 1, "before": {"keep": leaf, "tag": "parent"}, "after": {"keep": leaf, "tag": "parent"}, "inline": {"tag": "own"}},
                    {"id": 2, "snapshots": [leaf, {"keep": leaf, "tag": "parent"}]}]
        return {"cases": cases, "sharedValues": {leaf_key: leaf, parent_key: parent}}, expanded, leaf_key, parent_key

    def test_shared_values_expand_recursively_and_leave_the_record_otherwise_intact(self):
        row, expanded, _, _ = self.shared_record()
        resolved = validator["resolve_shared"](row)
        self.assertEqual(resolved["cases"], expanded)
        self.assertEqual(resolved["sharedValues"], row["sharedValues"])
        plain = {"cases": [{"id": 1}], "metrics": {"cases": 1}}
        self.assertEqual(validator["resolve_shared"](plain), plain)

    def test_shared_values_are_digest_bound_and_references_must_resolve(self):
        row, _, leaf_key, parent_key = self.shared_record()
        for key in (leaf_key, parent_key):
            changed = copy.deepcopy(row)
            changed["sharedValues"][key]["tag"] = "tampered"
            with self.subTest(key=key), self.assertRaisesRegex(AssertionError, "shared value digest differs"):
                validator["resolve_shared"](changed)
        changed = copy.deepcopy(row)
        changed["cases"][0]["before"] = {"$sharedRef": "sha256:" + "0" * 64}
        with self.assertRaisesRegex(AssertionError, "shared reference unresolved"):
            validator["resolve_shared"](changed)
        changed = copy.deepcopy(row)
        changed["sharedValues"] = {leaf_key: row["sharedValues"][leaf_key], parent_key: {"keep": {"$sharedRef": "sha256:" + "1" * 64}}}
        with self.assertRaisesRegex(AssertionError, "shared value digest differs"):
            validator["resolve_shared"](changed)

    def test_qualification_digest_binds_the_compacted_record_before_expansion(self):
        row, _, leaf_key, _ = self.shared_record()
        digest, encoded = validator["digest"], validator["encoded"]
        envelope = {"sandboxAdmission": validator["sandbox_admission"](), "schema": "legion-dotnet-sdk-accuracy/1",
                    "provider": "code.dotnet", "qualificationEligible": True, "productionQualification": False, "modelCalls": 0,
                    "kind": "dotnet-code-command-sdk-constructed", "claimScope": "known-answer-fixture-cases",
                    "executionPath": "native-sdk-frozen-plan-self-sourced-code", "status": "observed-known-answer-controls",
                    "missingControls": [], "executedScope": list(validator["TASKS"])}

        def sealed(record):
            return dict(record, qualificationDigest=digest(encoded(record)))

        # The compacted bytes verify and expand; the record then stops at the first check that needs
        # fields this stand-in omits (the source binding).
        with self.assertRaises(KeyError):
            validator["validate"](ROOT, sealed(dict(envelope, **row)))
        tampered = copy.deepcopy(row)
        tampered["sharedValues"][leaf_key]["tag"] = "tampered"
        # Editing a shared value without resealing breaks the qualification digest first.
        stale = dict(sealed(dict(envelope, **row)), sharedValues=tampered["sharedValues"])
        with self.assertRaisesRegex(AssertionError, "qualification bytes changed"):
            validator["validate"](ROOT, stale)
        # A resealed edit is caught by the stored value's own digest.
        with self.assertRaisesRegex(AssertionError, "shared value digest differs"):
            validator["validate"](ROOT, sealed(dict(envelope, **tampered)))

    def receipt_row(self, state, extra=()):
        request = dict.fromkeys(validator["REQUEST_FIELDS"])
        receipt = dict.fromkeys(validator["RECEIPT_FIELDS"] | set(extra))
        receipt["state"] = state
        return {"request": request, "executionReceipt": receipt, "stdout": None, "stderr": None}

    def test_only_owner_admission_refusals_carry_the_frozen_execution_policy_fields(self):
        policy_fields = ("executionPolicy", "executionPolicyIdentity")
        self.assertEqual(validator["POLICY_RECEIPT_FIELDS"], validator["RECEIPT_FIELDS"] | set(policy_fields))
        # An accepted field set proceeds to the first case lookup (no case is supplied), a differing
        # one stops at the exact-set check.
        for state in ("completed", "failed"):
            with self.subTest(state=state, extra=False), self.assertRaises(KeyError):
                validator["execution"](self.receipt_row(state), {}, {}, False)
            for extra in (policy_fields, policy_fields[:1], policy_fields[1:]):
                with self.subTest(state=state, extra=extra), self.assertRaisesRegex(AssertionError, "request/receipt fields differ"):
                    validator["execution"](self.receipt_row(state, extra), {}, {}, False)
        with self.subTest(state="unauthorized_effect", extra=policy_fields), self.assertRaises(KeyError):
            validator["execution"](self.receipt_row("unauthorized_effect", policy_fields), {}, {}, False)
        for extra in ((), policy_fields[:1], policy_fields[1:], policy_fields + ("unbound",)):
            with self.subTest(state="unauthorized_effect", extra=extra), self.assertRaisesRegex(AssertionError, "request/receipt fields differ"):
                validator["execution"](self.receipt_row("unauthorized_effect", extra), {}, {}, False)

    def test_native_family_has_exact_provider_stage_and_selector(self):
        entry = {"provider": "code.dotnet", "family": "dotnet-sdk", "stage": "finding"}
        self.assertEqual(gate["adapter"](ROOT, entry), ("dotnet-sdk", "dotnet_sdk_accuracy", "canonical-json", gate["DOTNET_SDK_SELECTOR"]))
        self.assertEqual(gate["DOTNET_SDK_HARNESS"], ["audit_cargo_test", "--lib", gate["DOTNET_SDK_SELECTOR"], "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"])
        for changed in ({"provider": "code.rust"}, {"stage": "candidate"}):
            with self.assertRaises(AssertionError):
                gate["adapter"](ROOT, dict(entry, **changed))

    def test_unexecuted_partial_or_wrong_surface_cannot_qualify(self):
        entry = {"provider": "code.dotnet", "family": "dotnet-sdk", "scope": "known-answer-fixture-cases"}
        for row in ({}, {"provider": "code.dotnet", "schema": "legion-dotnet-sdk-accuracy/1", "qualificationEligible": False},
                    {"provider": "code.dotnet", "schema": "legion-dotnet-sdk-accuracy/1", "productionQualification": True},
                    {"provider": "code.dotnet", "schema": "legion-dotnet-sdk-accuracy/1", "executedScope": ["build"]}):
            with self.assertRaises(AssertionError):
                gate["controls"](row, entry)

    def test_schema_requires_original_native_evidence_only_for_dotnet_family(self):
        schema = json.loads((ROOT / gate["SCHEMA"]).read_bytes())["$defs"]
        self.assertIn("dotnet-sdk", schema["entry"]["properties"]["family"]["enum"])
        evidence = schema["dotnetSdkEvidence"]
        self.assertFalse(evidence["additionalProperties"])
        self.assertEqual(set(evidence["required"]), set(gate["DOTNET_SDK_EVIDENCE"]))
        self.assertEqual(set(evidence["properties"]), set(gate["DOTNET_SDK_EVIDENCE"]))
        rule = next(r for r in schema["entry"]["allOf"] if r["if"]["properties"]["family"]["const"] == "dotnet-sdk")
        self.assertEqual(rule["then"], {"required": ["dotnetSdkEvidence"], "properties": {"provider": {"const": "code.dotnet"}, "stage": {"const": "finding"}}})
        self.assertEqual(rule["else"], {"not": {"required": ["dotnetSdkEvidence"]}})

    def test_original_child_and_enrollment_reference_inventory_is_closed(self):
        self.assertEqual(gate["DOTNET_SDK_EVIDENCE"], {"childExecution": "child-execution.json", "childStdout": "child.stdout.log", "childStderr": "child.stderr.log", "dotnetEnrollment": "dotnet-sdk-enrollment.json", "providerRecord": "code_dotnet.json"})
        for refs in ({}, {"arbitraryPath": {}}, {**dict.fromkeys(gate["DOTNET_SDK_EVIDENCE"], {}), "extra": {}}):
            with self.assertRaises(AssertionError):
                gate["dotnet_sdk_evidence"](ROOT, {"dotnetSdkEvidence": refs}, {})

    def test_log_binds_dedicated_artifact_marker_and_validator_summary(self):
        # Parser-only synthetic data cannot satisfy record_binding/provenance.
        row = {"provider": "code.dotnet"}
        locator = {"provider": "code.dotnet", "digest": "sha256:" + "1" * 64}
        validated = {"provider": "code.dotnet", "qualificationEligible": True}
        summary = {"records": [validated], "modelCalls": 0}
        lines = ["DOTNET_CODE_COMMAND_SDK_ACCURACY_ARTIFACT " + json.dumps(locator),
                 "DOTNET_CODE_COMMAND_SDK_ACCURACY_SUMMARY " + json.dumps(summary)]
        with tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP", "/Volumes/D/scratch")) as directory:
            path = Path(directory) / "log"
            path.write_text("\n".join(lines))
            observed = gate["log_evidence"](path, row, validated, "dotnet-sdk", locator)
            self.assertEqual(observed[1:], (1, 2))
            for malformed in ([lines[0], lines[0], lines[1]], [lines[0]], [lines[0].replace("DOTNET_", "PYTHON_"), lines[1]]):
                path.write_text("\n".join(malformed))
                with self.assertRaises(AssertionError):
                    gate["log_evidence"](path, row, validated, "dotnet-sdk", locator)

    def test_diagnostic_parser_binds_real_hashed_finding_reference(self):
        # This parser unit contains no SDK receipt & cannot qualify a provider.
        source = b"public class Answer { public int Double(int x) => x * 2; }\n"
        relative = "csharp/Answer.cs"
        rule = "dotnet:CA1822"
        finding = validator["digest"](("code.dotnet\0" + rule + "\0" + relative + "\0" + "1").encode())
        case = {"language": "csharp", "policyDefinition": {"scratch": "/native/scratch"}, "nativeResult": {
            "findings": [{"id": finding, "severity": "warning"}], "details": {
                "findingEvidence": {finding: {"provider": "code.dotnet", "ruleId": rule, "path": relative, "line": 1, "message": "Mark member static"}},
                "findingLocations": {finding: [relative + ":1"]}}}}
        raw = "/native/scratch/cache/dotnet-source/csharp/Answer.cs(1,34): warning CA1822: Mark member static"
        validator["positive_finding"](case, {relative: source}, raw)
        case["nativeResult"]["findings"] = [{"id": "sha256:" + "0" * 64, "severity": "warning"}]
        with self.assertRaises(AssertionError):
            validator["positive_finding"](case, {relative: source}, raw)
        with self.assertRaises(ValueError):
            validator["positive_finding"](case, {relative: source}, raw.replace("/native/scratch/cache/dotnet-source", "/unbound"))
