#!/usr/bin/env python3
"""Strict retained native test controls. Never creates evidence, admits jobs or promotes providers.

Authentication comes from maintainer-owned CI retrieval & pinned host enrollment.
Local byte checks cannot establish CI origin. Missing positive signed jobs always fail.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

ID = "legacy.quality.test"
FAMILY = "quality-test-native"
FAMILY_SCOPE = "constructed native SDK controls with authentic RustRight attestation; original denominator"
HARNESS = "engine/crates/legion-audit/tests/real_quality_test_accuracy.rs"
CORPUS = "engine/crates/legion-audit/tests/fixtures/quality-test/controls.json"
VALIDATOR = "scripts/ci/audit-quality-test-accuracy.py"
CONTROL_IDS = ("nonempty-pass", "nonempty-fail", "malformed-source", "descendant-reap",
               "no-enrollment", "invalid-enrollment", "client-pin-mismatch", "unregistered-runner",
               "malformed-runner-pin", "source-drift", "manifest-drift", "lock-drift", "config-drift",
               "admission-missing", "admission-denied", "execution-denied", "sandbox-missing",
               "tamper-signature", "tamper-output-digest", "timeout", "cancellation")
CRATES = ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")
SOURCE_ROOTS = ["engine/crates/" + name + "/src" for name in CRATES] + ["src/registry/rules", "src/registry/controls"]
SOURCE_FILES = ["engine/crates/" + name + "/Cargo.toml" for name in CRATES] + ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HARNESS, VALIDATOR, CORPUS, "scripts/ci/provision-quality-test-native.py", "scripts/ci/tests/test_quality_test_interruption.py"]


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def parsed(raw):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def regular(root, relative):
    require(isinstance(relative, str) and relative and "\\" not in relative and ":" not in relative, "unsafe retained path")
    rel = PurePosixPath(relative)
    require(not rel.is_absolute() and str(rel) == relative and ".." not in rel.parts, "noncanonical retained path")
    path = Path(root)
    require(path.is_absolute() and path.is_dir() and not path.is_symlink(), "unsafe retained root")
    for component in rel.parts:
        path /= component
        require(not path.is_symlink(), "retained ancestor symlink")
    require(path.is_file(), "retained file absent: " + relative)
    return path


def generated_session_provenance(relative):
    return re.fullmatch(
        r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json",
        relative,
    ) is not None


def source_files(root):
    files = set(SOURCE_FILES)
    for prefix in SOURCE_ROOTS:
        directory = root / prefix
        require(directory.is_dir() and not directory.is_symlink(), "source closure root absent")
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "source closure symlink")
            if path.is_file():
                if generated_session_provenance(path.relative_to(root).as_posix()):
                    continue
                files.add(path.relative_to(root).as_posix())
    return sorted(files)


def stream(evidence, case, receipt, key):
    artifact = receipt[key]
    if artifact is None:
        require(receipt["processTree"]["started"] is False, "launched command lacks retained stream")
        return b""
    require(artifact["immutable"] is True and type(artifact["bytes"]) is int, "mutable/invalid stream")
    raw = regular(evidence, case["caseId"] + "/run/artifacts/" + artifact["path"]).read_bytes()
    require(len(raw) == artifact["bytes"] and digest(raw) == artifact["digest"], "raw stream authentication differs")
    return raw


def envelope(status):
    receipt = status.get("receipt", status)
    provenance = receipt["provenance"]
    require(provenance["schema"] == "rustright.provenance.v1", "unknown signature envelope")
    signature = provenance["signature"]
    require(signature["alg"] == "ES256" and re.fullmatch(r"[0-9a-f]{128}", signature["value"]) is not None, "invalid broker signature form")
    return provenance["payload"], signature


def pin_valid(pin):
    require(pin["schemaVersion"] == 1 and pin["host"] and Path(pin["clientExecutable"]).is_absolute(), "public enrollment differs")
    for key in ("keyId", "brokerDigest", "clientDigest"):
        require(re.fullmatch(r"[0-9a-f]{64}", pin[key]) is not None, "invalid enrollment digest")
    require(re.fullmatch(r"04[0-9a-f]{128}", pin["publicKey"]) is not None, "invalid enrollment public key")
    require(hashlib.sha256(bytes.fromhex(pin["publicKey"])).hexdigest() == pin["keyId"], "enrollment key identity mismatch")


def interruption_process(case, request, receipt, auxiliary=False):
    """Parse actual native interruption facts; retained copy alone proves none."""
    control = case["caseId"]
    require(control in ("timeout", "cancellation"), "interruption outside declared control")
    state = receipt["state"]
    expected = "timeout" if control == "timeout" or auxiliary else "cancelled"
    require(state == expected and receipt["complete"] is False
            and receipt["policy"]["allowed"] is True and receipt["gaps"] == [state], "CLI did not prove matching admitted interruption")
    tree = receipt["processTree"]
    require(tree["started"] is True and tree["terminated"] is True and tree["reaped"] is True
            and type(tree["hardKilled"]) is bool, "interrupted CLI termination/reap unconfirmed")
    prefix = state + ": cooperative termination then bounded hard cleanup; "
    errno = r"(?:None|Some\([0-9]+\))"
    detail = prefix + r"term_errno=" + errno + r", kill_errno=" + errno + r", post_reap_probe_errno=" + errno + r", post_reap_group_absent=(?:None|Some\((?:true|false)\))"
    require(isinstance(tree["detail"], str) and re.fullmatch(detail, tree["detail"]) is not None, "native interruption cleanup detail differs")
    signal, exit_code = receipt["signal"], receipt["exitCode"]
    if signal is None:
        require(type(exit_code) is int and 0 <= exit_code <= 255, "interrupted child lacks authentic Unix terminal status")
    else:
        require(type(signal) is int and signal in (9, 15) and exit_code is None
                and (signal != 9 or tree["hardKilled"] is True), "unbounded/unrelated Unix termination signal")
    timing = receipt["timing"]
    require(set(timing) == {"startedAtMs", "completedAtMs", "durationMs"}
            and all(type(v) is int and v >= 0 for v in timing.values())
            and timing["completedAtMs"] >= timing["startedAtMs"]
            and timing["durationMs"] == timing["completedAtMs"] - timing["startedAtMs"], "interruption timing differs")
    require(type(request["timeoutMs"]) is int and request["timeoutMs"] > 0, "interrupted request has no bound")
    if state == "timeout":
        require(timing["durationMs"] >= request["timeoutMs"], "timeout preceded request deadline")
    elif not auxiliary:
        same(case["events"][1].get("cancellation"), {"delayMs":1500,"fired":True}, "native cancellation trigger never fired")


def verify_interrupted(case, operations, streams):
    require(case["caseId"] in ("timeout", "cancellation"), "retained-copy control identity differs")
    require(operations in (["request-digest", "cargo"], ["request-digest", "cargo", "cancel", "status"]), "interruption lacks exact native submit chain")
    probe, submit = streams[:2]
    require(probe[3]["receipt"]["state"] == "completed" and probe[3]["receipt"]["complete"] is True
            and probe[3]["receipt"]["policy"]["allowed"] is True, "interruption probe never completed")
    event, receipt = submit[3], submit[3]["receipt"]
    require(event["originalRequest"]["args"] == ["cargo", "test"], "interrupted submit command differs")
    interruption_process(case, event["executedRequest"], receipt)
    ids = re.findall(r"(?m)^rightkit: request ([A-Za-z0-9_-]{1,128})$", submit[2].decode("utf-8"))
    require(len(ids) == 1, "interruption lacks real broker submit request identity")
    if case["caseId"] == "timeout":
        require(case["frozenProvider"]["bounds"]["timeoutMs"] == 2500
                and event["originalRequest"]["timeoutMs"] <= 2500, "timeout control did not use frozen bounded deadline")
    for operation, _, _, cleanup in streams[2:]:
        require(cleanup["originalRequest"]["args"] == [operation, ids[0]], "cleanup targeted unrelated broker request")
    result = case["nativeResult"]
    reason = result["details"]["testCommandResolution"]["reason"]
    allowed_reasons = ("cancelled-or-timed-out",) if case["caseId"] == "timeout" else ("cancelled-after-submit-launch", "cancelled-or-timed-out")
    require(reason in allowed_reasons and "disposable-copy-incomplete:" + reason in result["coverage"]["gaps"], "native incomplete reason does not prove this interruption")
    expected_chain = ["request-digest", "cargo"] if reason == "cancelled-after-submit-launch" else ["request-digest", "cargo", "cancel", "status"]
    same(operations, expected_chain, "native interruption reason differs from observed command chain")
    copy = event["originalRequest"]["cwd"]
    same(case["copyPathsAfter"], {copy:True}, "interrupted submit copy was removed/replaced")
    require(result["details"]["disposableCopy"]["copyPath"] == copy, "native retained copy detached from interrupted submit")
    native = result["details"]["executionReceipt"]
    if reason == "cancelled-after-submit-launch":
        require(native["state"] == "internal" and native["complete"] is False
                and native["processTree"]["detail"] == "launch and cleanup state unobserved", "provider's unknown cancellation state was replaced")
    else:
        for key in ("receiptId", "requestId", "state", "complete", "cwd", "exitCode", "signal", "processTree", "timing", "gaps"):
            same(native[key], receipt[key], "native result detached from interrupted process: " + key)


def validate_events(evidence, case, pin):
    operations = []
    parsed_streams = []
    for event in case["events"]:
        request, executed, receipt = event["originalRequest"], event["executedRequest"], event["receipt"]
        require(request["providerId"] == ID and request["planId"] == case["planDigest"] and request["taskId"] == "test"
                and request["executable"] == pin["clientExecutable"] and request["expectedDigest"] == "sha256:" + pin["clientDigest"]
                and request["shell"] is False and request["skipVersionProbe"] is True, "native effect request binding differs")
        require(Path(request["cwd"]).parent == Path(case["scratchRoot"]) and Path(request["cwd"]).name.startswith("test-copy-"), "effect escaped disposable copy")
        operation = request["args"][0]
        require(operation in ("request-digest", "cargo", "status", "cancel", "verify-receipt"), "unexpected managed command")
        operations.append(operation)
        if case["caseId"] == "sandbox-missing":
            same(executed, dict(request, requiresNetworkSandbox=True), "sandbox control changed unrelated request")
        else:
            same(executed, request, "transport changed native request")
        require(receipt is not None, "missing real terminal process receipt")
        require(receipt["providerId"] == ID and receipt["planId"] == case["planDigest"] and receipt["cwd"] == request["cwd"]
                and receipt["requestId"] == request["requestId"] and receipt["receiptId"] == "receipt:" + request["requestId"]
                and receipt["taskId"] == "test", "receipt request identity differs")
        policy = receipt["policy"]
        require(policy and policy["id"] == "legion-quality-test-constructed-sdk-v1" and policy["version"] == 1, "missing explicit SDK admission")
        stdout, stderr = stream(evidence, case, receipt, "stdout"), stream(evidence, case, receipt, "stderr")
        if receipt["processTree"]["started"]:
            require(receipt["executable"]["canonicalPath"] == pin["clientExecutable"] and receipt["executable"]["digest"] == "sha256:" + pin["clientDigest"], "actual client differs from enrolled pin")
            require(receipt["executable"]["versionSkipped"] is True, "project test runner probed outside attestation")
            require(receipt["processTree"]["terminated"] is True and receipt["processTree"]["reaped"] is True, "native CLI process not terminal & reaped")
            if receipt["state"] in ("timeout", "cancelled"):
                require(operation in ("cargo", "cancel", "status"), "interrupted unrelated native operation")
                interruption_process(case, executed, receipt, auxiliary=operation != "cargo")
            else:
                require(receipt["signal"] is None, "signal outside proven native interruption")
        parsed_streams.append((operation, stdout, stderr, event))
    return operations, parsed_streams


def verify_terminal(evidence, case, pin, streams):
    require([row[0] for row in streams] == ["request-digest", "cargo", "status", "verify-receipt"], "missing genuine positive execution chain")
    probe, submit, status, verification = streams
    for row in streams:
        receipt = row[3]["receipt"]
        require(receipt["state"] == "completed" and receipt["complete"] is True and receipt["policy"]["allowed"] is True, "positive job used incomplete/denied CLI operation")
    request_digest = parsed(probe[1])["requestDigest"]
    require(re.fullmatch(r"[0-9a-f]{64}", request_digest) is not None, "request digest missing")
    probe_request = probe[3]["originalRequest"]
    require(probe_request["args"][:2] == ["request-digest", "--core"] and len(probe_request["args"]) == 3, "request core probe differs")
    core_path = Path(probe_request["args"][2])
    require(core_path.parent == Path(case["scratchRoot"]), "request core escaped scratch")
    core = parsed(regular(evidence, case["caseId"] + "/run/" + core_path.name).read_bytes())
    require(hashlib.sha256(encoded(core)).hexdigest() == request_digest, "request core digest not independently reconstructed")
    same(parsed(parsed(probe[1])["canonical"]), core, "client canonical request core differs")
    status_json = parsed(status[1])
    verify_args = verification[3]["originalRequest"]["args"]
    require(verify_args.count("--receipt") == 1, "verifier input missing/duplicated")
    status_input = Path(verify_args[verify_args.index("--receipt") + 1])
    require(status_input.parent == Path(case["scratchRoot"]), "status input escaped retained scratch")
    require(regular(evidence, case["caseId"] + "/run/" + status_input.name).read_bytes() == status[1], "verifier input differs from original broker status")
    payload, signature = envelope(status_json)
    verified = parsed(verification[1])
    require(verified["ok"] is True and verified["payload"] == payload, "pinned real verifier did not accept exact retained signed payload")
    require(signature["keyId"] == pin["keyId"] and payload["keyId"] == pin["keyId"] and payload["host"] == pin["host"]
            and payload["broker"]["brokerDigest"] == pin["brokerDigest"] and payload["broker"]["clientDigest"] == pin["clientDigest"], "signed enrollment binding differs")
    request = payload["request"]
    submit_request = submit[3]["originalRequest"]
    require(request["kind"] == "cargo" and request["shim"] == "cargo" and request["adapter"] is None
            and request["requestedArgv"] == ["test"] and submit_request["args"] == ["cargo", "test"]
            and request["workspace"] == submit_request["cwd"] and request["workspaceRoot"] == submit_request["cwd"], "signed runner/source boundary differs")
    require(payload["requestDigest"] == request_digest and payload["nonce"] == submit_request["environment"]["RIGHTKIT_ATTEST_NONCE"], "fresh signed request binding differs")
    require(core["shim"] == "cargo" and core["adapter"] is None and core["requestedArgv"] == ["test"]
            and core["nonce"] == payload["nonce"] and core["workspace"] == request["workspace"]
            and core["outputs"] == request["outputs"], "signed request core scope differs")
    manifest = core["inputManifest"]
    require(manifest["root"] == request["workspace"] and request["outputs"] == [request["workspace"] + "/target"], "manifest/output boundary differs")
    expected_inputs = case["sourceAtExecution"]
    actual_inputs = {entry["path"]: "sha256:" + entry["sha256"] for entry in manifest["entries"]}
    same(actual_inputs, expected_inputs, "signed input manifest reduced source closure")
    require(len(manifest["entries"]) == len(expected_inputs) and all(entry["kind"] == "file" for entry in manifest["entries"]), "input manifest duplicated/non-file entry")
    require(payload["jobId"] == status_json["id"] and payload["jobId"] in submit[2].decode("utf-8", errors="strict"), "submitted/status job identity differs")
    expected_exit = 0 if case["control"]["expected"] == "pass" else 101
    result = payload["result"]
    require(result["status"] == ("SUCCEEDED" if expected_exit == 0 else "FAILED") and result["exitCode"] == expected_exit
            and result["signal"] is None and result["reap"] == {"reaped": True, "status": "REAPED"}
            and submit[3]["receipt"]["exitCode"] == expected_exit, "actual test exit differs")
    require(payload["descendants"]["status"] == "tree-contained" and payload["descendants"].get("survivors", []) == [], "signed descendants not contained")
    require(payload["inputBoundary"]["status"] == "intact" and all(payload["inputBoundary"][key] == [] for key in ("added", "deleted", "changed")), "signed source boundary violated")
    require(re.fullmatch(r"[0-9a-f]{64}", payload["outputDigest"]) is not None, "signed output digest absent")
    broker_output = verification[3]["brokerOutput"]
    require(broker_output["file"] == "broker-output.bin" and broker_output["truncated"] is False, "complete authenticated broker output missing")
    log = status_json["receipt"]["output"]["log"]
    original_log, log_root = Path(broker_output["originalPath"]), Path(broker_output["logRoot"])
    require(original_log.is_absolute() and log_root.is_absolute() and original_log != log_root
            and ".." not in original_log.parts and ".." not in log_root.parts and original_log.is_relative_to(log_root)
            and broker_output["originalPath"] == log["path"] and broker_output["statusInput"] == str(status_input)
            and log["truncated"] is False and type(log["bytes"]) is int and 0 <= log["bytes"] <= 8*1024*1024,
            "original owner broker status/log paths or bounds differ")
    output_path = regular(evidence, case["caseId"] + "/broker-output.bin")
    require(output_path.stat().st_size <= 8*1024*1024, "retained broker output exceeds bound")
    raw = output_path.read_bytes()
    require(len(raw) <= 8*1024*1024 and len(raw) == log["bytes"] and len(raw) == broker_output["bytes"] == status_json["receipt"]["output"]["bytes"]
            and digest(raw) == broker_output["digest"] == "sha256:" + payload["outputDigest"]
            and status_json["receipt"]["output"]["digest"] == payload["outputDigest"], "retained raw broker output does not match signature")
    if case["caseId"] == "nonempty-pass":
        require(b"running 1 test" in raw and b"qualification_nonempty_pass ... ok" in raw and b"1 passed; 0 failed" in raw, "empty or fabricated passing suite")
    elif case["caseId"] == "nonempty-fail":
        require(b"running 1 test" in raw and b"qualification_nonempty_fail ... FAILED" in raw and b"0 passed; 1 failed" in raw and b"LEGION_QUALITY_FAIL_41" in raw, "missing genuine failing test")
    elif case["caseId"] == "malformed-source":
        require(b"E0425" in raw and b"no_such_function_qualification" in raw, "missing genuine compiler failure")
    elif case["caseId"] == "descendant-reap":
        require(b"qualification_descendant ... ok" in raw, "descendant fixture was not executed")
    details = case["nativeResult"]["details"]
    require(details["attestedRuns"]["verified"] is True and details["disposableCopy"]["sourceUnchanged"] is True
            and details["disposableCopy"]["copyUnchanged"] is True and details["rustRightVerifiedResult"]["jobId"] == payload["jobId"], "native result lost authentic provenance")
    require(case["copyPathsAfter"] and all(value is False for value in case["copyPathsAfter"].values()), "terminal disposable copy was not removed")


def required_evidence_files(record):
    """Exact allowlist for archiving source, native streams, request core & signed raw output."""
    paths = set()
    for case in record["cases"]:
        prefix = case["caseId"] + "/"
        for source in case["fixtureFiles"]:
            paths.add(prefix + "source/" + source)
        for event in case["events"]:
            request = event["originalRequest"]
            if event["receipt"]:
                for stream_name in ("stdout", "stderr"):
                    artifact = event["receipt"][stream_name]
                    if artifact:
                        paths.add(prefix + "run/artifacts/" + artifact["path"])
            if request["args"][0] == "request-digest":
                path = Path(request["args"][2])
                require(path.parent == Path(case["scratchRoot"]), "core path outside scratch")
                paths.add(prefix + "run/" + path.name)
            elif request["args"][0] == "verify-receipt":
                path = Path(request["args"][request["args"].index("--receipt") + 1])
                require(path.parent == Path(case["scratchRoot"]), "verifier input outside scratch")
                paths.add(prefix + "run/" + path.name)
            if event.get("brokerOutput"):
                require(event["brokerOutput"]["file"] == "broker-output.bin", "unexpected broker output artifact")
                paths.add(prefix + "broker-output.bin")
        for copy, exists in case["copyPathsAfter"].items():
            if exists:
                path = Path(copy)
                require(path.parent == Path(case["scratchRoot"]) and path.name.startswith("test-copy-"), "retained copy path escaped scratch")
                for source in case["fixtureFiles"]:
                    paths.add(prefix + "run/" + path.name + "/" + source)
    return sorted(paths)


def validate_record(repository_root, record, evidence_root=None, live=False):
    root = Path(repository_root).resolve()
    require(record["schema"] == "legion-quality-test-native-accuracy/1" and record["provider"] == ID
            and record["family"] == FAMILY and record["stage"] == "finding"
            and record["claimScope"] == FAMILY_SCOPE
            and record["executionPath"] == "native-frozen-plan-disposable-copy-real-rustright", "dedicated identity differs")
    for key in ("productionQualification", "wholeProviderQualified", "auditCleanClaim", "osSandboxQualified"):
        require(record[key] is False, "expanded qualification claim: " + key)
    require(type(record["modelCalls"]) is int and record["modelCalls"] == 0, "unexpected model calls")
    require(record["qualificationDigest"] == digest(encoded({k:v for k,v in record.items() if k != "qualificationDigest"})), "record seal differs")
    specs = [item for item in parsed(regular(root, "src/registry/providers.json").read_bytes())["providers"] if item["id"] == ID]
    require(len(specs) == 1, "provider registry missing/duplicated")
    spec = {key:value for key,value in specs[0].items() if key != "benchmark"}
    binding = record["binding"]
    same(binding["providerSpec"], spec, "original provider contract changed")
    require(record["providerVersion"] == spec["providerVersion"] and binding["providerSpecDigest"] == digest(encoded(spec)) and binding["fixture"] == HARNESS, "provider binding differs")
    sources = {name:digest(regular(root, name).read_bytes()) for name in source_files(root)}
    same(binding["sources"], sources, "source closure stale/incomplete")
    require(binding["sourcesDigest"] == digest(encoded(sources)), "source closure digest differs")
    contract = parsed(regular(root, CORPUS).read_bytes())
    require(tuple(control["id"] for control in contract["cases"]) == CONTROL_IDS and tuple(case["caseId"] for case in record["cases"]) == CONTROL_IDS, "missing/duplicated/reordered required control")
    pin = record["hostEnrollment"]; pin_valid(pin)
    require(record["hostEnrollmentDigest"] == digest(encoded(pin)), "enrollment seal differs")
    evidence = Path(evidence_root or record["evidenceRoot"]).resolve()
    require(evidence.is_dir() and not evidence.is_symlink() and (not live or not evidence.is_relative_to(root)), "evidence root missing/unsafe")
    for path in required_evidence_files(record):
        regular(evidence, path)
    jobs = set()
    for control, case in zip(contract["cases"], record["cases"]):
        same(case["control"], control, "source-owned control changed")
        original_root = Path(record["evidenceRoot"])
        require(Path(case["sourceRoot"]) == original_root / case["caseId"] / "source"
                and Path(case["scratchRoot"]) == original_root / case["caseId"] / "run", "case source/scratch identity differs")
        files = dict(contract["commonFiles"], **{"src/lib.rs":contract["programs"][control["program"]]})
        files.update(control.get("files", {}))
        same(case["fixtureFiles"], files, "native fixtures differ")
        before = {name:digest(raw.encode()) for name,raw in files.items()}
        same(case["sourceBeforeFreeze"], before, "frozen fixture hashes differ")
        execution = dict(before)
        if "afterFreeze" in control:
            execution[control["afterFreeze"]["path"]] = digest(control["afterFreeze"]["text"].encode())
        same(case["sourceAtExecution"], execution, "drift control not applied")
        same(case["sourceAfter"], execution, "original fixture modified during execution")
        enrollment = dict(pin)
        if control["mode"] == "invalid-enrollment":
            enrollment["schemaVersion"] = 0
        elif control["mode"] == "client-pin-mismatch":
            enrollment["clientDigest"] = "00" * 32
        elif control["mode"] == "unregistered-runner":
            enrollment["adapters"] = {}
        same(case["enrollment"], enrollment, "enrollment control mutation differs")
        for name, expected in execution.items():
            require(digest(regular(evidence, case["caseId"] + "/source/" + name).read_bytes()) == expected, "retained original fixture differs")
        frozen = case["frozenProvider"]
        same(frozen["configuration"]["selector"], spec["selector"], "selector changed to reduce denominator")
        inventory = case["inventory"]
        require(inventory["schemaVersion"] == 1 and inventory["digest"] == digest(encoded([1, inventory["repositoryId"], inventory["generation"], inventory["entries"]])), "frozen inventory seal differs")
        same({entry["path"]:entry["digest"] for entry in inventory["entries"]}, before, "frozen inventory reduced fixture closure")
        selected = {entry["path"]:entry for entry in inventory["entries"] if entry["path"] in ("package.json", "Cargo.toml", "src-tauri/Cargo.toml")}
        scripted = [entry for entry in inventory["entries"] if "test" in entry["packageScripts"]]
        if scripted:
            selected.update({entry["path"]:entry for entry in inventory["entries"] if entry["sourceFile"]})
        selected_entries = [selected[path] for path in sorted(selected)]
        denominator = frozen["configuration"]["denominatorCount"]
        require(type(denominator) is int and denominator == len(selected_entries) and denominator > 0
                and frozen["configuration"]["denominatorDigest"] == digest(encoded([inventory["digest"], spec["selector"], selected_entries])), "empty/changed denominator")
        result = case["nativeResult"]
        require(result["coverage"]["denominator_digest"] == frozen["configuration"]["denominatorDigest"]
                and result["coverage"]["expected"] == denominator, "result denominator changed")
        operations, streams = validate_events(evidence, case, pin)
        expected = control["expected"]
        if expected in ("pass", "finding"):
            require(result["complete"] is True and len(result["findings"]) == int(expected == "finding") and result["coverage"]["expected"] == denominator
                    and result["coverage"]["examined"] == denominator and result["coverage"]["gaps"] == [], "native outcome/coverage differs")
            verify_terminal(evidence, case, pin, streams)
            job = result["details"]["rustRightVerifiedResult"]["jobId"]
            require(job not in jobs, "job reused between controls"); jobs.add(job)
        else:
            require(result["complete"] is False and result["findings"] == [] and result["coverage"]["examined"] == 0 and result["coverage"]["gaps"], "refusal became clean/finding")
            require(result["details"].get("attestedRuns", {}).get("verified") is not True, "incomplete control claimed verified test execution")
            if expected == "incomplete-retained":
                verify_interrupted(case, operations, streams)
            elif control["id"].startswith("tamper-"):
                require(operations == ["request-digest", "cargo", "status", "verify-receipt"], "tamper control lacks real prior signed job")
                event = streams[-1][3]; mutation = event["mutation"]
                before_raw, after_raw = bytes(mutation["before"]), bytes(mutation["after"])
                require(before_raw != after_raw and before_raw == streams[-2][1] and mutation["kind"] == control["mode"], "tamper input not derived from actual signed receipt")
                require(event["receipt"]["processTree"]["started"] is True and parsed(streams[-1][1])["ok"] is False, "real pinned verifier did not refuse tamper")
            elif control["id"] in ("execution-denied", "sandbox-missing"):
                require(operations == ["request-digest"] and streams[0][3]["receipt"]["processTree"]["started"] is False, "prelaunch refusal started client")
                require(streams[0][3]["receipt"]["state"] == ("sandbox_missing" if control["id"] == "sandbox-missing" else "unauthorized_effect"), "incorrect SDK refusal state")
            else:
                require(not operations, "invalid source/enrollment/admission launched broker client")
                reason = result["details"].get("testCommandResolution", {}).get("reason", "")
                expected_reasons = {
                    "no-enrollment":"managed-test-trust-not-configured",
                    "invalid-enrollment":"test-enrollment-invalid:",
                    "client-pin-mismatch":"managed-test-attestation-cli-unavailable",
                    "unregistered-runner":"managed-test-runner-not-registered:npm",
                    "malformed-runner-pin":"test-package-manager-pin-invalid",
                    "source-drift":"source-digest-drift:src/lib.rs",
                    "manifest-drift":"test-source-input-drift:Cargo.toml",
                    "lock-drift":"test-source-input-drift:Cargo.lock",
                    "config-drift":"source-digest-drift:.cargo/config.toml",
                }
                if control["id"] in expected_reasons:
                    require(expected_reasons[control["id"]] in reason, "refusal reason does not match control")
                elif control["id"] in ("admission-missing", "admission-denied"):
                    receipt = result["details"]["executionReceipt"]
                    require(receipt["policy"]["allowed"] is False and receipt["processTree"]["started"] is False, "missing explicit admission refusal receipt")
    return {"provider":ID,"stage":"finding","scope":"constructed native SDK controls; production admission denied; timeout/cancel conservatively retained",
            "coverageState":"scoped-controls-complete","qualificationDigest":record["qualificationDigest"],"metrics":{"cases":len(CONTROL_IDS),"matched":len(CONTROL_IDS),"mismatched":0}}


def mutation_checks(root, record, evidence):
    """Exercise adversarial resealing against genuine baseline, never construct positive proof."""
    import copy
    validate_record(root, record, evidence)
    def interrupted(row, control):
        return next(case for case in row["cases"] if case["caseId"] == control)
    def submit(row, control):
        return next(event for event in interrupted(row, control)["events"] if event["originalRequest"]["args"][0] == "cargo")
    attacks = {
        "missing-positive": lambda row: row["cases"].pop(0),
        "reused-case": lambda row: row["cases"].__setitem__(1, copy.deepcopy(row["cases"][0])),
        "denominator-reduction": lambda row: row["cases"][0]["frozenProvider"]["configuration"].__setitem__("denominatorCount", 0),
        "stale-enrollment": lambda row: row["hostEnrollment"].__setitem__("clientDigest", "00" * 32),
        "invented-verification": lambda row: row["cases"][0]["events"][-1]["receipt"]["stdout"].__setitem__("digest", "sha256:" + "00" * 32),
        "raw-output-tamper": lambda row: row["cases"][0]["events"][-1]["brokerOutput"].__setitem__("digest", "sha256:" + "00" * 32),
        "false-cleanup": lambda row: row["cases"][-1].__setitem__("copyPathsAfter", {next(iter(row["cases"][-1]["copyPathsAfter"])):False}),
        "missing-source-binding": lambda row: row["binding"]["sources"].pop(HARNESS),
        "production-promotion": lambda row: row.__setitem__("productionQualification", True),
        "unsigned-positive": lambda row: row["cases"][0]["events"].pop(),
        "failed-submit-is-not-timeout": lambda row: submit(row, "timeout")["receipt"].update(state="failed", signal=None, exitCode=1, gaps=["failed"]),
        "output-limit-is-not-timeout": lambda row: submit(row, "timeout")["receipt"].update(state="output_limited", gaps=["output_limited"]),
        "missing-cancel-receipt": lambda row: submit(row, "cancellation").__setitem__("receipt", None),
        "wrong-interruption-control": lambda row: submit(row, "cancellation")["receipt"].__setitem__("state", "timeout"),
        "unrelated-signal": lambda row: submit(row, "timeout")["receipt"].__setitem__("signal", 11),
        "unreaped-interruption": lambda row: submit(row, "cancellation")["receipt"]["processTree"].__setitem__("reaped", False),
        "missing-cancellation-trigger": lambda row: submit(row, "cancellation")["cancellation"].__setitem__("fired", False),
        "unrelated-native-retention": lambda row: interrupted(row, "timeout")["nativeResult"]["details"]["testCommandResolution"].__setitem__("reason", "rightkit-submit-process-unconfirmed"),
    }
    for name, mutate in attacks.items():
        changed = copy.deepcopy(record); mutate(changed)
        changed.pop("qualificationDigest")
        changed["qualificationDigest"] = digest(encoded(changed))
        try:
            validate_record(root, changed, evidence)
        except (AssertionError, KeyError, ValueError, TypeError):
            continue
        raise AssertionError("strict validator accepted resealed attack: " + name)
    return sorted(attacks)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("record", type=Path)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--mutation-checks", action="store_true")
    args = parser.parse_args()
    row = parsed(args.record.read_bytes())
    validated = validate_record(args.repository_root, row, args.evidence_root, live=True)
    if args.mutation_checks:
        validated["rejectedResealedAttacks"] = mutation_checks(args.repository_root, row, args.evidence_root)
    print("QUALITY_TEST_NATIVE_ACCURACY_SUMMARY " + json.dumps({"records":[validated],"modelCalls":0}, sort_keys=True))


if __name__ == "__main__":
    main()
