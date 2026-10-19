#!/usr/bin/env python3
"""Validate original JVM/v1 SDK known-answer observations; no tool execution.

Source-bound validation is separate from authenticated CI retrieval/provenance.
Whole original Java/Kotlin/.kts/Scala matrix is required; no production admission.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

HARNESS = "engine/crates/legion-audit/tests/real_jvm_sdk_accuracy.rs"
FIXTURES = "scripts/ci/fixtures/audit-code-jvm-sdk"
INPUTS = "scripts/ci/audit-jvm-sdk-inputs.json"
SCOPE = "constructed frozen Gradle JVM/v1 controls on macOS arm64; compiler diagnostic lint only; no arbitrary-project or production owner-admission claim"
POLICY = "legion-jvm-sdk-known-answer-v1"
TASKS = ("wrapper", "compile", "lint", "test", "dependency")
CONTROLS = ("positive", "nonempty-clean", "compile-error", "test-failure", "no-op-test", "missing-dependency", "wrapper-drift", "source-drift", "dependency-drift", "enrollment-drift", "unsupported-variant", "missing-tool", "rejected-admission", "absent-sandbox", "request-mutation")
SOURCE_ROOTS = ["engine/crates/" + c + "/src" for c in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")] + ["src/registry/rules", "src/registry/controls", FIXTURES]
SOURCE_FILES = [HARNESS, INPUTS, "scripts/ci/provision-jvm-sdk.py", "scripts/ci/audit-jvm-sdk-accuracy.py", "engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", "src/registry/providers.json"] + ["engine/crates/" + c + "/Cargo.toml" for c in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")]
ORIGINAL = {"extensions": ["java", "kt", "kts", "scala"], "variants": [["java", ["java"]], ["kotlin", ["kt", "kts"]], ["scala", ["scala"]]], "tools": list(TASKS), "context": ["sourceSets"]}


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def safe_file(root, relative):
    require(isinstance(relative, str) and "\\" not in relative, "unsafe relative path")
    rel = PurePosixPath(relative)
    require(not rel.is_absolute() and str(rel) == relative and all(p not in ("..", ".") for p in rel.parts), "escaping source path")
    path = root
    for part in rel.parts:
        path /= part
        require(not path.is_symlink(), "source symlink refused")
    require(path.is_file(), "source/retained file missing: " + relative)
    return path


def source_files(root):
    files = set(SOURCE_FILES)
    for relative in SOURCE_ROOTS:
        path = root / relative
        require(path.is_dir() and not path.is_symlink(), "source closure root missing")
        for item in path.rglob("*"):
            require(not item.is_symlink(), "source closure symlink")
            if item.is_file():
                relative = item.relative_to(root).as_posix()
                if "/.audit/arcane/receipts/session-provenance/" not in relative:
                    files.add(relative)
    return sorted(files)


def source_digest(root, relative):
    """Execution semantics exclude mutable qualification metadata, as shared gate does."""
    raw = safe_file(root, relative).read_bytes()
    if relative == "src/registry/providers.json":
        registry = parsed(raw)
        for provider in registry["providers"]:
            provider.pop("benchmark", None)
        return digest(encoded(registry))
    return digest(raw)


def retained_files(record):
    # Fixed names only: original record, enrollment, confinement & every child stream.
    return ["code_jvm.json", "enrollment.json", "confinement.json"] + [
        control + "/child." + stream + ".log" for control in CONTROLS for stream in ("stdout", "stderr")]


def artifact_locator(record, raw):
    return {"schema": "legion-jvm-sdk-artifact/1", "provider": "code.jvm", "file": "code_jvm.json",
            "digest": digest(raw), "bytes": len(raw), "qualificationDigest": record["qualificationDigest"],
            "qualificationEligible": record["qualificationEligible"], "productionQualification": False}


def absolute(value):
    require(isinstance(value, str) and not any(c in value for c in "\0\r\n\\"), "unsafe absolute path")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts and not value.startswith("//"), "noncanonical absolute path")
    return path


def stream(record, artifact, artifact_root, live):
    if record is None:
        require(artifact is None, "absent raw artifact has receipt")
        return b""
    require(set(record) == {"path", "absolutePath", "digest", "bytes", "immutable", "rawBytes"}, "raw stream fields differ")
    require(isinstance(record["rawBytes"], list) and all(type(b) is int and 0 <= b <= 255 for b in record["rawBytes"]), "raw stream bytes malformed")
    raw = bytes(record["rawBytes"])
    require(record["immutable"] is True and record["bytes"] == len(raw) and record["digest"] == digest(raw), "raw stream digest differs")
    require(artifact == {k: record[k] for k in ("path", "digest", "bytes", "immutable")}, "original SDK artifact linkage differs")
    path = absolute(record["absolutePath"])
    rel = PurePosixPath(record["path"])
    require(not rel.is_absolute() and str(rel) == record["path"] and rel.parts and all(p not in ("..", ".") for p in rel.parts), "unsafe SDK artifact path")
    require(path == absolute(str(artifact_root)) / rel, "original artifact location differs")
    if live:
        require(Path(path).is_file() and not Path(path).is_symlink() and Path(path).read_bytes() == raw, "live raw artifact changed")
    return raw


def native_request(row, case, enrollment, retained, live):
    require(set(row) == {"providerRequest", "request", "executionReceipt", "stdout", "stderr"}, "execution row differs")
    req, receipt = row["request"], row["executionReceipt"]
    task = req["taskId"]
    require(task in TASKS and re.fullmatch(r"legion-audit/[0-9a-f]{64}", req["requestId"]), "request task/identity differs")
    stage = absolute(req["cwd"])
    require(stage.name == "jvm-source" and stage.parent.name == "tmp", "staged cwd differs")
    scratch = stage.parent.parent
    java = absolute(enrollment["toolchains"]["jdk"]["root"]) / "bin/java"
    home = scratch / "cache/jvm-owned/home"
    def args(task):
        agent = home / "wrapper/dists/gradle-9.2.1-bin/2t0n5ozlw9xmuyvbp7dnzaxug/gradle-9.2.1/lib/agents/gradle-instrumentation-agent-9.2.1.jar"
        temp = scratch / "cache/jvm-owned/tmp"
        daemon_args = "-Xmx512m -Xms256m -XX:MaxMetaspaceSize=384m -XX:+HeapDumpOnOutOfMemoryError -Dfile.encoding=UTF-8 -Duser.language=en -Duser.country=US -Duser.variant= -Djava.io.tmpdir=" + str(temp)
        out = ["-Xmx512m", "-Xms256m", "-XX:MaxMetaspaceSize=384m", "-XX:+HeapDumpOnOutOfMemoryError", "-Dfile.encoding=UTF-8", "-Duser.language=en", "-Duser.country=US", "-Duser.variant=", "-Djava.io.tmpdir=" + str(temp), "-javaagent:" + str(agent), "-Dgradle.user.home=" + str(home), "-cp", str(stage / "gradle/wrapper/gradle-wrapper.jar"), "org.gradle.wrapper.GradleWrapperMain", "-Dorg.gradle.jvmargs=" + daemon_args, "--offline", "--no-daemon", "--console=plain", "--no-configuration-cache", "--gradle-user-home", str(home), "--project-cache-dir", str(scratch / "cache/jvm-owned/project")]
        return out + (["--version"] if task == "wrapper" else ["--rerun-tasks", {"compile": "legionCompile", "lint": "legionLint", "test": "legionTest", "dependency": "legionDependency"}[task]])
    profile_text = '(version 1)\n(allow default)\n(deny network*)\n(deny file-write* (subpath "' + str(stage).replace('"', '\\"') + '"))\n(allow network-bind (local udp "*:0"))\n'
    sha = digest(profile_text.encode()).removeprefix("sha256:")
    prefix = ["-f", str(scratch / "sandbox" / ("audit-gradle-" + sha + ".sb")), "--", str(java)]
    expected_args = prefix + args(task)
    if case["control"] == "request-mutation":
        expected_args.append("--refresh-dependencies")
    require(req["args"] == expected_args and req["versionArgs"] == prefix + args("wrapper"), "wrapper/native argv differs")
    require(req["executable"] == "/usr/bin/sandbox-exec" and is_digest(req["expectedDigest"]), "native authenticator identity differs")
    require(req["providerId"] == "code.jvm" and req["planId"] == case["planDigest"] and req["policyId"] == "audit" and req["origin"] == "TargetProject" and req["shell"] is False and req["acceptedExitCodes"] == [0], "SDK scope differs")
    require(req["schemaVersion"] == 1 and req["timeoutMs"] == 120000 and req["stdoutLimit"] == req["stderrLimit"] == 33554432 and req["skipVersionProbe"] is False and req["versionRequirement"] is None and req["sensitiveArgumentIndexes"] == req["sensitiveEnvironmentNames"] == [], "SDK limits/probe/sensitivity differ")
    require(req["requiresNetworkSandbox"] is True, "network authenticator not required")
    expected_sandbox = None if case["control"] == "absent-sandbox" else {"id": "sandbox:macos:gradle-bind-only:" + sha, "network": True, "filesystemScope": str(stage)}
    require(req["sandbox"] == expected_sandbox, "sandbox binding differs")
    env = req["environment"]
    base = {"PATH", "PATHEXT", "SystemRoot", "COMSPEC", "HOME", "USERPROFILE"}
    expected = {k: env[k] for k in base if k in env}
    expected.update({"PATH": str(java.parent) + ":/usr/bin:/bin", "JAVA_HOME": str(java.parent.parent), "GRADLE_USER_HOME": str(home), "LEGION_KOTLIN_HOME": enrollment["toolchains"]["kotlin"]["root"], "LEGION_SCALA_HOME": enrollment["toolchains"]["scala"]["root"], "LEGION_JVM_BUILD": str(scratch / "cache/jvm-owned/build"), "NO_COLOR": "1", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1"})
    for name, relative in (("TMPDIR", "tmp"), ("TEMP", "tmp"), ("TMP", "tmp"), ("XDG_CACHE_HOME", "cache/xdg"), ("CARGO_TARGET_DIR", "cache/cargo-target"), ("npm_config_cache", "cache/npm"), ("RUFF_CACHE_DIR", "cache/ruff"), ("MYPY_CACHE_DIR", "cache/mypy"), ("PYTHONPYCACHEPREFIX", "cache/pycache"), ("GOCACHE", "cache/go-build")):
        expected[name] = str(scratch / relative)
    require(env == expected and req["environmentAllowlist"] == sorted(base | set(expected)), "unsealed environment or allowlist differs")
    original = dict(req)
    if case["control"] == "absent-sandbox":
        original["sandbox"] = {"id": "sandbox:macos:gradle-bind-only:" + sha, "network": True, "filesystemScope": str(stage)}
    if case["control"] == "request-mutation":
        original["args"] = original["args"][:-1]
    require(row["providerRequest"] == original, "SDK boundary control changed extra fields")
    for key in ("schemaVersion", "requestId", "providerId", "planId", "taskId", "cwd"):
        require(receipt[key] == req[key], "original SDK receipt/request linkage differs")
    require(receipt["policyId"] == ("audit-native-owner-admission-v1" if case["control"] == "rejected-admission" else POLICY), "SDK policy owner differs")
    require(receipt["command"] is None or receipt["command"]["args"] == req["args"], "original command args changed")
    stdout = stream(row["stdout"], receipt["stdout"], scratch / "artifacts", live)
    stderr = stream(row["stderr"], receipt["stderr"], scratch / "artifacts", live)
    raw = (stdout + b"\n" + stderr).decode("utf-8")
    require("Downloading " not in raw and "Unzipping " not in raw, "runtime wrapper bootstrap attempted")
    if live:
        require(digest(Path(req["executable"]).read_bytes()) == req["expectedDigest"], "authenticator drift")
    return task, raw


def validate_confinement(record, root, retained, live):
    descriptor = record["confinement"]
    require(descriptor["file"] == "confinement.json", "confinement route differs")
    raw = safe_file(retained, descriptor["file"]).read_bytes()
    require(len(raw) == descriptor["bytes"] and digest(raw) == descriptor["digest"], "confinement record drift")
    proof = parsed(raw)
    require(proof["schema"] == "legion-gradle-bind-confinement/1" and proof["complete"] is True, "native confinement incomplete")
    require(proof["sourceDigest"] == digest(safe_file(root, "engine/crates/legion-effects/src/gradle_sandbox.rs").read_bytes()), "confinement compiled source differs")
    require([r["mode"] for r in proof["controls"]] == ["confinement", "hang", "orphan"], "native confinement/lifecycle denominator changed")
    for row in proof["controls"]:
        mode, req, receipt = row["mode"], row["request"], row["receipt"]
        project = absolute(req["cwd"])
        require(project.name == "project" and project.parent.name == "gradle-native-control", "native confinement project differs")
        profile_text = '(version 1)\n(allow default)\n(deny network*)\n(deny file-write* (subpath "' + str(project).replace('"', '\\"') + '"))\n(allow network-bind (local udp "*:0"))\n'
        sha = digest(profile_text.encode())
        require(row["profile"] == profile_text and row["profileDigest"] == sha, "bind-only owner profile differs")
        require(req["executable"] == "/usr/bin/sandbox-exec" and req["args"][:3] == ["-f", str(project.parent / "profiles" / ("audit-gradle-" + sha[7:] + ".sb")), "--"], "native control not wrapped")
        require(req["args"][4:] == ["--exact", "gradle_sandbox::tests::gradle_bind_only_worker", "--ignored", "--nocapture"], "native control entry differs")
        require(receipt["requestId"] == "gradle-native-" + mode and receipt["providerId"] == "shared-gradle-confinement" and receipt["policyId"] == "gradle-bind-native-control" and receipt["planId"] == digest(b"gradle-bind-only-native-v1") and receipt["cwd"] == req["cwd"], "native receipt identity differs")
        require(receipt["state"] == ("timeout" if mode == "hang" else "completed") and receipt["complete"] is (mode != "hang") and receipt["processTree"]["started"] is True and receipt["processTree"]["terminated"] is True and receipt["processTree"]["reaped"] is True and receipt["gaps"] == (["timeout"] if mode == "hang" else []), "native process tree unconfirmed")
        require(receipt["policy"]["allowed"] is True and receipt["policy"]["digest"] == sha and receipt["sandbox"] == {"required": True, "receiptId": "sandbox:macos:gradle-bind-only:" + sha[7:], "networkEnabled": True}, "native policy/sandbox linkage differs")
        require(receipt["command"]["args"] == req["args"] and receipt["command"]["executable"] == req["executable"], "native command differs")
        stdout = stream(row["stdout"], receipt["stdout"], project.parent / mode / "artifacts", live).decode()
        stream(row["stderr"], receipt["stderr"], project.parent / mode / "artifacts", live)
        require(all(type(p["pid"]) is int and p["pid"] > 1 and p["stopped"] is True for p in row["descendants"]), "native descendants remain live")
        require([p["role"] for p in row["descendants"]] == ([mode] if mode == "confinement" else [mode, "grandchild"]), "native descendant denominator differs")
        if mode == "confinement":
            require(all("LEGION_NATIVE_DENIALS|ipv" + f + "|assigned-bind,udp-send,udp-receive,inherited-send,inherited-receive,tcp-bind,tcp-connect" in stdout for f in ("4", "6")) and "LEGION_NATIVE_DENIALS|external|udp,tcp,inherited-tcp-send,inherited-tcp-receive,project-write" in stdout and "LEGION_GRADLE_BIND_ONLY_CONFINEMENT|pass" in stdout, "native denial/readiness controls missing")


def validate(record, root, retained, live=False):
    require(record["schema"] == "legion-jvm-sdk-accuracy/1" and record["provider"] == "code.jvm" and record["operationContract"] == "jvm/v1" and record["harness"] == HARNESS, "record route differs")
    original = dict(record)
    q = original.pop("qualificationDigest")
    require(q == digest(encoded(original)), "qualification digest differs")
    require(record["qualificationEligible"] is True and record["productionQualification"] is False and record["sourceUnchanged"] is True, "qualification scope/eligibility differs")
    require(record["scope"] == SCOPE, "JVM scoped claim differs")
    require(record["originalContract"] == ORIGINAL and record["controls"] == list(CONTROLS), "original contract/control denominator changed")
    closure = {p: source_digest(root, p) for p in source_files(root)}
    require(record["sourceClosure"] == closure, "original implementation/fixture closure differs")
    spec = next(v for v in parsed(safe_file(root, "src/registry/providers.json").read_bytes())["providers"] if v["id"] == "code.jvm")
    spec.pop("benchmark", None)
    require(record["providerSpec"] == spec and spec["selector"] == {"op": "always"}, "original source selector/provider spec differs")
    validate_confinement(record, root, retained, live)
    descriptor = record["enrollment"]
    require(descriptor["file"] == "enrollment.json", "enrollment route differs")
    raw_enrollment = safe_file(retained, descriptor["file"]).read_bytes()
    require(len(raw_enrollment) == descriptor["bytes"] and digest(raw_enrollment) == descriptor["digest"], "retained enrollment changed")
    enrollment = parsed(raw_enrollment)
    pins_bytes = safe_file(root, INPUTS).read_bytes()
    pins = parsed(pins_bytes)
    require(enrollment["schema"] == "legion-jvm-sdk-enrollment/1" and enrollment["platform"] == pins["platform"] == "darwin-arm64" and enrollment["versions"] == pins["versions"] and enrollment["lockDigest"] == digest(pins_bytes), "original tool enrollment differs")
    for item in pins["assets"]:
        actual = enrollment["assets"][item["id"]]
        require({k: actual[k] for k in item} == item, "official asset pin differs")
        absolute(actual["path"])
        if live:
            require(digest(Path(actual["path"]).read_bytes()) == item["sha256"], "live archive drift")
    require(set(enrollment["toolchains"]) == {"jdk", "gradle", "kotlin", "scala"}, "incomplete native toolchain closure")
    for runtime in enrollment["toolchains"].values():
        absolute(runtime["root"])
        require(runtime["files"] and all(is_digest(v) or v.startswith("symlink:") for v in runtime["files"].values()), "toolchain file closure malformed")
    require([c["control"] for c in record["cases"]] == list(CONTROLS) and [c["control"] for c in record["childExecutions"]] == list(CONTROLS), "case/child denominator changed")
    expected_gap = {"compile-error": "tool-failed", "test-failure": "tool-failed:test", "no-op-test": "test-assertions-incomplete", "missing-dependency": "dependency-artifact-identity", "wrapper-drift": "changed-since-inventory", "source-drift": "project-input-drift", "dependency-drift": "project-input-drift", "enrollment-drift": "toolchain-drift", "unsupported-variant": "source-set-denominator", "missing-tool": "closure-root", "rejected-admission": "native-owner-admission-unavailable", "absent-sandbox": "sandbox-missing", "request-mutation": "unauthorized_effect"}
    for case, child in zip(record["cases"], record["childExecutions"]):
        control = case["control"]
        require(case["matched"] is True and child["success"] is True and child["exitCode"] == 0, "control not matched by successful native harness")
        for key in ("stdout", "stderr"):
            desc = child[key]
            raw = safe_file(retained, desc["path"]).read_bytes()
            require(desc["path"] == control + "/child." + key + ".log" and len(raw) == desc["bytes"] and digest(raw) == desc["digest"], "child execution stream changed")
        native = case["nativeResult"]
        complete = control in ("positive", "nonempty-clean")
        require(native["complete"] is complete, "negative became clean or positive incomplete")
        require(case["provider"] == native["provider"] == "code.jvm", "provider changed")
        require(case["policyDefinition"]["id"] == POLICY and case["policyDefinition"]["projectFiles"] == case["fixtureSources"] and case["policyDefinition"]["planDigest"] == case["planDigest"] and case["policyDefinition"]["tasks"] == list(TASKS), "exact SDK policy closure differs")
        rows = case["sdkExecutions"]
        expected_count = 0 if control in ("wrapper-drift", "unsupported-variant", "missing-tool", "enrollment-drift") else 1 if control == "source-drift" else 5
        require(len(rows) == expected_count, "original SDK execution denominator changed")
        raw_by_task = {}
        for row in rows:
            task, raw = native_request(row, case, enrollment, retained, live)
            require(task not in raw_by_task, "duplicate SDK task")
            raw_by_task[task] = raw
            receipt = row["executionReceipt"]
            if control != "rejected-admission":
                decisions = [d for d in case["policyDecisions"] if d["requestId"] == row["request"]["requestId"]]
                require(len(decisions) == 1 and decisions[0]["request"] == row["request"] and decisions[0]["task"] == task and decisions[0]["allowed"] is (control != "request-mutation"), "original policy decision linkage differs")
                require(receipt["policy"]["digest"] == digest(encoded(case["policyDefinition"])) and receipt["policy"]["id"] == POLICY and receipt["policy"]["version"] == 1, "original policy definition binding differs")
            if control in ("rejected-admission", "request-mutation", "absent-sandbox"):
                require(receipt["state"] == ("sandbox_missing" if control == "absent-sandbox" else "unauthorized_effect") and receipt["processTree"]["started"] is False and receipt["complete"] is False, "refused request started or became complete")
            elif complete:
                require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["exitCode"] == 0 and receipt["processTree"]["started"] is True and receipt["processTree"]["reaped"] is True and receipt["policy"]["allowed"] is True and receipt["executable"]["version"]["qualified"] is True, "positive tool lacks original completed/versioned receipt")
        if complete:
            require(all("LEGION_GRADLE_LAUNCH_MODE|wrapper-main" in raw_by_task[t] for t in TASKS if t != "wrapper"), "inprocess Gradle not proven")
            require(set(raw_by_task) == set(TASKS) and native["coverage_gaps"] == [], "required original tools/context missing")
            require(native["coverage"]["expected"] == native["coverage"]["examined"] == len(case["fixtureSources"]), "source/context denominator narrowed")
            require(case["fixtureAfter"] == case["fixtureSources"], "positive input drift")
            require("Gradle 9.2.1" in raw_by_task["wrapper"] and "LEGION_COMPILE_DONE|java,kotlin,kts,scala" in raw_by_task["compile"], "native wrapper/compiler incomplete")
            lint = raw_by_task["lint"]
            require("LEGION_LINT_DONE|java,kotlin,kts,scala" in lint and all(re.search(r"^LEGION_NATIVE_EXIT\|" + language + r"\|[01]$", lint, re.M) for language in ("java", "kotlin", "kts", "scala")), "per-language lint execution missing")
            assertions = re.findall(r"^LEGION_ASSERT\|([^\r\n]+)$", raw_by_task["test"], re.M)
            require(len(assertions) == 4 and set(assertions) == {"java-answer|pass", "kotlin-answer|pass", "scala-answer|pass", "kts-answer|pass"} and "LEGION_PROJECT_TEST_DONE|4" in raw_by_task["test"], "real named test assertions missing/skipped")
            dependency = raw_by_task["dependency"]
            artifacts = re.findall(r"^LEGION_ARTIFACT\|runtimeClasspath\|([^|\r\n]+)\|(sha256:[0-9a-f]{64})$", dependency, re.M)
            require(len(artifacts) == 3 and {PurePosixPath(p).name for p, _ in artifacts} == {"support.jar", "kotlin-stdlib.jar", "scala-library.jar"} and "LEGION_DEPENDENCY_DONE|runtimeClasspath" in dependency and re.search(r"^LEGION_COMPONENT\|.*:support", dependency, re.M), "actual nonempty dependency closure missing")
            findings = native["details"]["findingEvidence"]
            if control == "positive":
                for language, ext in (("java", "java"), ("kotlin", "kt"), ("kts", "kts"), ("scala", "scala")):
                    require(any(f["ruleId"] == "jvm-compiler-warning:" + language and f["path"].endswith("." + ext) for f in findings.values()), "planted native language warning missed")
                    require(re.search(r"\." + ext + r":\d+(?::\d+)?: warning:", lint), "finding lacks native warning")
            else:
                require(findings == {}, "nonempty clean false positive")
        else:
            require(native["coverage_gaps"] and expected_gap[control] in encoded(native["coverage_gaps"]).decode(), "intended incomplete/refusal gap missing")
    return {"provider": "code.jvm", "qualificationDigest": q, "qualificationEligible": True, "productionQualification": False, "controls": len(CONTROLS), "scope": record["scope"]}


def validate_record(root, record, live=False, retained=None):
    require(retained is not None, "original JVM retained artifact root required")
    return validate(record, Path(root), Path(retained), live)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    retained = args.receipts.resolve(strict=True)
    record = parsed(safe_file(retained, "code_jvm.json").read_bytes())
    result = validate_record(args.root.resolve(strict=True), record, live=True, retained=retained)
    print("JVM_SDK_ACCURACY_SUMMARY " + json.dumps({"records": [result], "modelCalls": 0}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
