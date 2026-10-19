#!/usr/bin/env python3
"""Fixed OpenGrep constructed native SDK/artifact fixture gate only.

Does not qualify production admission, self-producing path or population accuracy.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

PROVIDER = "security.opengrep"
POLICY = "legion-opengrep-sdk-artifact-fixture-v1"
SCOPE = "constructed-native-sdk-artifact-fixture"
HARNESS = "engine/crates/legion-audit/tests/opengrep_accuracy.rs"
GATE = "scripts/ci/audit-opengrep-artifact-accuracy.py"
RULE = "src/registry/rules/opengrep/legion-core.yml"
TREES = ["engine/crates/legion-audit/src", "engine/crates/legion-effects/src", "engine/crates/legion-provider-sdk/src", "engine/crates/legion-contracts/src", "engine/crates/legion-rules/src", "src/registry/rules", "src/registry/controls"]
FILES = ["engine/Cargo.lock", "engine/Cargo.toml", *[f"engine/crates/{name}/Cargo.toml" for name in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")], HARNESS, GATE]
PINS = {"sha256:035dd8fd2410fe68513916df0c2895257fffafcd5314b4a118484ce8db62bedb", "sha256:2f0d0c7a41a3e48dc02c30dabc4851bc37c18f021b46c9ae54b15177ece088ee"}
FIXTURES = {
    "shell-planted": ('import os\nfrom flask import request\nos.system(request.args.get("cmd"))\n', ["legion-command-injection-shell|app.py|3"]),
    "sql-planted": ('from flask import request\ndef query(cursor):\n    cursor.execute(request.args.get("sql"))\n', ["legion-sql-interpolation|app.py|3"]),
    "clean": ('import os\nfrom flask import request\ndef query(cursor):\n    supplied = request.args.get("value")\n    print(supplied)\n    os.system("printf fixed")\n    cursor.execute("SELECT 1")\n', []),
}
EXPECTATION_SOURCES = [
    "https://github.com/opengrep/opengrep/releases/expanded_assets/v1.31.0",
    "https://raw.githubusercontent.com/opengrep/opengrep/v1.31.0/src/osemgrep/cli_scan/Scan_CLI.ml",
    "https://raw.githubusercontent.com/opengrep/opengrep/v1.31.0/src/osemgrep/networking/Rule_fetching.ml",
]

def require(value, message):
    if not value:
        raise ValueError(message)

def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()

def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()

def load(path):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON key")
        return dict(items)
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, f"non-JSON value {value}"))

def absolute(value):
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts and not value.startswith("//"), "unsafe retained absolute path")
    return path

def source_binding(root):
    out = {}
    for name in TREES + FILES:
        base = root / name
        require(base.exists() and not base.is_symlink(), f"missing/symlink source: {name}")
        for path in base.rglob("*") if base.is_dir() else [base]:
            require(not path.is_symlink(), "symlink in source closure")
            if path.is_file():
                out[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    return dict(sorted(out.items()))

def artifact(item):
    require(isinstance(item, dict) and item["immutable"] is True, "unsealed retained artifact")
    path = PurePosixPath(item["path"])
    require(not path.is_absolute() and ".." not in path.parts and str(path) == item["path"], "artifact escape")
    raw = item["raw"].encode()
    require(type(item["bytes"]) is int and item["bytes"] == len(raw) and item["digest"] == digest(raw), "artifact bytes differ")
    return raw

def inspect_case(case, rules, *, live):
    source, expected = FIXTURES[case["caseId"]]
    require(case["source"] == {"path": "app.py", "bytes": source, "digest": digest(source.encode())}, "fixed source control differs")
    require(case["productionQualification"] is False and case["executionPath"] == "native-sdk-command-contract-to-frozen-registry-artifact", "scope expanded")
    inventory, plan = case["inventory"], case["frozenPlan"]
    entry = {"path": "app.py", "symbols": [], "dependencies": [], "packageScripts": [], "sourceFile": True, "digest": digest(source.encode())}
    require(inventory["entries"] == [entry] and inventory["schemaVersion"] == 1 and inventory["repositoryId"] == case["caseId"], "inventory source denominator differs")
    require(inventory["generation"] == "filesystem:" + digest(canonical([entry])), "inventory generation differs")
    require(inventory["digest"] == digest(canonical([1, inventory["repositoryId"], inventory["generation"], [entry]])), "inventory seal differs")
    require(case["planDigest"] == digest(canonical(plan)), "frozen plan digest differs")
    require(case["planSignature"] == "hmac-sha256:" + hmac.new(b"opengrep-sdk-artifact-fixture-key", canonical(plan), hashlib.sha256).hexdigest(), "fixture plan HMAC differs")
    require(plan["inventoryDigest"] == inventory["digest"] and plan["inventoryGeneration"] == inventory["generation"] and len(plan["providers"]) == 1 and plan["providers"][0]["id"] == PROVIDER, "plan context differs")
    config = case["providerConfiguration"]
    require(config == plan["providers"][0]["configuration"] and config["selector"] == {"op": "always"} and config["denominatorCount"] == 1 and config["denominatorDigest"] == inventory["digest"], "frozen selector differs")
    policy = case["policy"]
    root, run = absolute(policy["root"]), absolute(policy["runDirectory"])
    require(root.name == "source" and run == root.parent / "run", "fixture root/run differ")
    tool = absolute(policy["tool"]["path"])
    require(not tool.is_relative_to(root.parent) and policy["tool"]["digest"] in PINS, "untrusted tool pin")
    if live:
        live_tool = Path(tool)
        require(live_tool.resolve() == live_tool and live_tool.is_file() and digest(live_tool.read_bytes()) == policy["tool"]["digest"], "live tool bytes differ")
    require(policy["tool"]["versionRequirement"] == "exact:1.31.0", "version pin differs")
    wrapper = absolute(policy["wrapper"]["path"])
    require(wrapper == PurePosixPath("/usr/bin/sandbox-exec")
            and re.fullmatch(r"sha256:[0-9a-f]{64}", policy["wrapper"]["digest"]) is not None, "native wrapper identity differs")
    if live:
        require(digest(Path(wrapper).read_bytes()) == policy["wrapper"]["digest"], "live native wrapper bytes differ")
    args = ["scan", "--json-output", str(run / "output.json"), "--sarif-output", str(run / "output.sarif"), "--metrics", "off", "--disable-version-check", "-f", str(run / "legion-core.yml"), "app.py"]
    require(policy["args"] == args and policy["id"] == POLICY and policy["version"] == 1 and policy["provider"] == PROVIDER and policy["scope"] == SCOPE, "policy contract differs")
    require(policy["planDigest"] == case["planDigest"] and policy["inventoryDigest"] == inventory["digest"] and policy["sourceDigest"] == digest(source.encode()) and policy["rulesDigest"] == digest(rules), "policy source identity differs")
    require(policy["timeoutMs"] == 30000 and policy["outputLimit"] == 4194304 and policy["sandbox"] == "native-macos-deny-network-deny-project-write", "policy bounds differ")
    env = policy["environment"]
    require(set(env) <= {"HOME", "PATH"} and env["HOME"] == str(run / "home"), "environment scope differs")
    receipt = case["actualExecutionReceipt"]
    require(receipt["schemaVersion"] == 1 and receipt["state"] == "completed" and receipt["complete"] is True and receipt["gaps"] == [] and receipt["exitCode"] == 0 and receipt["signal"] is None, "native execution incomplete")
    require(receipt["providerId"] == PROVIDER and receipt["planId"] == case["planDigest"] and receipt["policyId"] == POLICY and receipt["taskId"] == "opengrep-sdk-artifact" and receipt["cwd"] == str(root), "receipt context differs")
    require(receipt["receiptId"] == "receipt:" + receipt["requestId"] and re.fullmatch(r"legion-audit/[a-f0-9]{64}", receipt["requestId"]), "SDK request identity differs")
    require(receipt["processTree"]["started"] is True and receipt["processTree"]["terminated"] is True and receipt["processTree"]["reaped"] is True, "process tree unproven")
    require(receipt["policy"]["allowed"] is True and receipt["policy"]["id"] == POLICY and receipt["policy"]["version"] == 1 and receipt["policy"]["digest"] == digest(compact(policy)), "actual policy decision differs")
    command = receipt["command"]
    argv = command["args"]
    require(command["executable"] == str(wrapper) and argv[0] == "-f" and argv[2:4] == ["--", str(tool)] and argv[4:] == args and absolute(argv[1]).is_relative_to(run), "actual command differs")
    require(command["environmentNames"] == sorted(env) == receipt["environmentNames"] and command["redactedArgumentIndexes"] == command["redactedEnvironmentNames"] == [], "receipt environment/redaction differs")
    exe, sandbox = receipt["executable"], receipt["sandbox"]
    escaped = str(root).replace("\\", "\\\\").replace('"', '\\"')
    profile = f'(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath "{escaped}"))\n(deny file-write* (subpath "{escaped}"))\n'
    require(sandbox == {"required": True, "receiptId": "sandbox:macos:" + digest(profile.encode()).removeprefix("sha256:"), "networkEnabled": True}, "sandbox identity differs")
    require(exe["requestedPath"] == exe["canonicalPath"] == str(wrapper) and exe["digest"] == policy["wrapper"]["digest"] and exe["digestState"] == "sealed", "executable receipt differs")
    version = exe["version"]
    require(version["qualified"] is True and version["skippedByPolicy"] is False and version["exitCode"] == 0 and version["args"] == argv[:4] + ["--version"] and re.search(r"(?<![\w.])v?1\.31\.0(?![\w.])", version["output"]), "native version unproven")
    for stream in ("stdout", "stderr"):
        artifact(receipt[stream])
    require(len(case["policyDecisions"]) == 1 and case["policyDecisions"][0] == {"allowed": True, "requestId": receipt["requestId"], "args": argv, "versionArgs": version["args"], "planId": case["planDigest"], "providerId": PROVIDER, "policyId": POLICY}, "observed policy request differs")
    output = json.loads(artifact(case["jsonOutput"]))
    sarif = json.loads(artifact(case["sarifOutput"]))
    require(output["errors"] == [] and output["paths"]["scanned"] == ["app.py"] and sarif["version"] == "2.1.0", "actual scanner output incomplete")
    labels = [f'{item["check_id"]}|{item["path"]}|{item["start"]["line"]}' for item in output["results"]]
    require(labels == expected == case["expected"] == case["actual"] and case["controlMatched"] is True, "fixed exact rule/path/line control differs")
    require(len(sarif["runs"]) == 1 and [f'{item["ruleId"]}|{item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]}|{item["locations"][0]["physicalLocation"]["region"]["startLine"]}' for item in sarif["runs"][0].get("results", [])] == expected, "SARIF candidate correspondence differs")
    input_ = case["actualArtifactInput"]
    evidence = input_["artifacts"]["opengrep"]
    bound = {"repositoryRevision": inventory["generation"], "digest": inventory["digest"]}
    require(input_["projection"] == {"files": [{"path": "app.py"}]} and input_["plan"]["denominator"] == {"pathCount": 1}, "artifact source projection differs")
    require(evidence["binding"] == input_["plan"]["binding"] == bound and evidence["denominator"] == {"digest": inventory["digest"], "expected": 1, "examined": 1}, "artifact authority differs")
    augmented = dict(receipt)
    augmented["tool"] = {"name": "opengrep", "version": version["output"], "executableDigest": policy["tool"]["digest"]}
    augmented["stdoutArtifact"] = receipt["stdout"]
    augmented["jsonOutputArtifact"] = {key: case["jsonOutput"][key] for key in ("digest", "bytes")}
    require(evidence["executionReceipt"] == augmented and evidence["tool"] == augmented["tool"], "artifact receipt fabricated/different")
    require(evidence["ruleset"] == {"schemaVersion": 1, "kind": "legion-opengrep-ruleset", "path": str(run / "legion-core.yml"), "digest": digest(rules), "license": None, "source": RULE, "version": None}, "shipped rules binding differs")
    candidates = evidence["candidates"]
    require(len(candidates) == len(expected), "candidate count differs")
    for candidate, raw in zip(candidates, output["results"]):
        require(candidate["provider"] == PROVIDER and candidate["providerVersion"] == version["output"] and candidate["ruleId"] == raw["check_id"] and candidate["claim"] == raw["extra"]["message"] and candidate["denominatorDigest"] == inventory["digest"] and candidate["verdict"] == "UNADJUDICATED" and candidate["adjudicationRequired"] is True, "candidate meaning differs")
        # Native JSON's optional extra.dataflow_trace is not admitted by this
        # normalizer. This corpus qualifies rule/path/line pattern candidates;
        # it does not qualify trace extraction or interfile reachability.
        require(candidate["detectorMetadata"] == {"capability": "pattern", "source": None, "sink": None, "intermediateVars": []}, "unexpected trace/capability scope")
        body = {"provider": PROVIDER, "ruleId": raw["check_id"], "file": "app.py", "line": 3, "traceDigest": None}
        require(candidate["id"] == digest(b"opengrep-candidate\x00" + compact(body)), "candidate ID lost fixed source location")
        require(candidate["binding"] is None and candidate["candidateClass"] == "sast" and candidate["evidenceRefs"] == [] and candidate["uncertainty"] == ["A pattern match is never a vulnerability by itself; adjudication is required."], "candidate assurance scope differs")
    result = case["actualProviderResult"]
    require(result["provider"] == PROVIDER and result["applicable"] is True and result["complete"] is True and result["findings"] == result["coverage_gaps"] == result["degradation"] == [], "native provider incomplete")
    require(result["coverage"] == {"denominator_digest": inventory["digest"], "expected": 1, "examined": 1, "gaps": []}, "provider frozen coverage differs")
    require(result["details"]["candidates"] == candidates and result["details"]["executionReceipt"] == augmented and "availability" not in result["details"], "native artifact route differs")
    missing = case["missingContextProviderResult"]
    require(missing["complete"] is False and missing["findings"] == [] and missing["details"]["analysis"]["coverageGaps"] == [{"kind": "opengrep-evidence-missing"}], "missing context incorrectly complete")

def validate_record(root, row, *, live=True):
    """Validate retained native evidence; offline mode never authenticates CI or installed bytes."""
    body = dict(row); body.pop("qualificationDigest")
    require(row["qualificationDigest"] == digest(compact(body)), "record digest differs")
    require(row["schema"] == "legion-opengrep-sdk-artifact-accuracy/1" and row["provider"] == PROVIDER and row["stage"] == "candidate" and row["scope"] == SCOPE and row["productionQualification"] is False and row["selfProducerQualification"] is False and row["modelCalls"] == 0, "scope changed")
    require(row["qualificationEligible"] is True and row["status"] == "pass", "controls failed")
    require(row["expectationSources"] == EXPECTATION_SOURCES and row["metrics"] == {"truePositives": 2, "falsePositives": 0, "falseNegatives": 0, "positiveCases": 2, "cleanCases": 1}, "control metric/source inventory differs")
    bound = row["binding"]
    registry = load(root / "src/registry/providers.json")
    spec = next(item for item in registry["providers"] if item["id"] == PROVIDER)
    spec.pop("benchmark", None)
    require(bound["providerSpec"] == spec and bound["harnessPath"] == HARNESS, "provider spec/harness differs")
    sources = source_binding(root)
    require(bound["sources"] == sources and bound["sourcesDigest"] == digest(canonical(sources)), "source closure differs")
    rules = (root / RULE).read_bytes()
    require(bound["rules"] == {"path": RULE, "bytes": rules.decode(), "digest": digest(rules)}, "rules source differs")
    require([case["caseId"] for case in row["cases"]] == list(FIXTURES), "case inventory differs")
    for case in row["cases"]:
        inspect_case(case, rules, live=live)
    return {"provider": PROVIDER, "stage": "candidate", "scope": SCOPE, "status": "pass",
            "productionQualification": False, "selfProducerQualification": False,
            "qualificationDigest": row["qualificationDigest"], "metrics": row["metrics"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    path = args.receipts / "security_opengrep_sdk_artifact.json"
    require(path.is_file() and not path.is_symlink(), "missing/symlink actual record")
    # CI always rebinds actual installed executable bytes; only registration is offline.
    checked = validate_record(args.root, load(path), live=True)
    print("OPENGREP_SDK_ARTIFACT_ACCURACY_SUMMARY " + compact({"records": [checked], "modelCalls": 0}).decode())

if __name__ == "__main__":
    main()
