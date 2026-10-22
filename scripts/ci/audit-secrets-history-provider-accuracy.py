#!/usr/bin/env python3
"""Native synthetic current/history evidence only; no tools, promotion or CI authentication.

Live mode checks current source/tool paths. Offline mode never resolves recorded CI
paths: all raw streams, files & Git objects must be embedded in authenticated record.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

PROVIDER = "secrets.current-history"
SELECTOR = "native_providers::security::producer::history_qualification_tests::native_current_history_qualification"
SCRIPT = "scripts/ci/audit-secrets-history-provider-accuracy.py"
SECURITY = "engine/crates/legion-audit/src/native_providers/security/"
SOURCES = [
    "engine/Cargo.lock",
    "engine/Cargo.toml",
    "engine/crates/legion-audit/Cargo.toml",
    "engine/crates/legion-audit/src/continuation.rs",
    "engine/crates/legion-audit/src/dag.rs",
    "engine/crates/legion-audit/src/error.rs",
    "engine/crates/legion-audit/src/execution.rs",
    "engine/crates/legion-audit/src/execution_policy.rs",
    "engine/crates/legion-audit/src/graph_context.rs",
    "engine/crates/legion-audit/src/integrity.rs",
    "engine/crates/legion-audit/src/inventory.rs",
    "engine/crates/legion-audit/src/lib.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/backend.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/common.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/compatibility.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/core.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/data.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/docs.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/docs_contract.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/evidence.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/framework.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/frontend.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/mod.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/producer.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/requirements.rs",
    "engine/crates/legion-audit/src/native_providers/architecture/test_quality.rs",
    "engine/crates/legion-audit/src/native_providers/availability.rs",
    "engine/crates/legion-audit/src/native_providers/code/applicability.rs",
    "engine/crates/legion-audit/src/native_providers/code/common.rs",
    "engine/crates/legion-audit/src/native_providers/code/dotnet.rs",
    "engine/crates/legion-audit/src/native_providers/code/evidence.rs",
    "engine/crates/legion-audit/src/native_providers/code/javascript.rs",
    "engine/crates/legion-audit/src/native_providers/code/jvm.rs",
    "engine/crates/legion-audit/src/native_providers/code/long_tail.rs",
    "engine/crates/legion-audit/src/native_providers/code/mobile.rs",
    "engine/crates/legion-audit/src/native_providers/code/mod.rs",
    "engine/crates/legion-audit/src/native_providers/code/native_commands.rs",
    "engine/crates/legion-audit/src/native_providers/code/python.rs",
    "engine/crates/legion-audit/src/native_providers/code/rust.rs",
    "engine/crates/legion-audit/src/native_providers/code/tools.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/accessibility.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/accessibility_internal_suite.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/adapter.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/candidate_suites.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/common.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/framework.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/framework_major_suite.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/governance.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/governance_ownership.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/governance_policy.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/mod.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/visual.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/visual_core.rs",
    "engine/crates/legion-audit/src/native_providers/legacy/visual_png.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/attested_runs.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/contracts.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/disposable_copy.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/mod.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/node_outdated.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/parsers.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/python_requirements.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/registry.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/resolver.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/runtime_capture.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/rust_outdated.rs",
    "engine/crates/legion-audit/src/native_providers/legacy_checks/semgrep.rs",
    "engine/crates/legion-audit/src/native_providers/mod.rs",
    "engine/crates/legion-audit/src/native_providers/p11d_quality/mod.rs",
    "engine/crates/legion-audit/src/native_providers/p11d_quality/security_suite.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/candidate_routing.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/coverage_plan.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/coverage_regressions.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/excerpts.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/followup.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/ingest.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/lens_plan.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/lens_schemas.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/mod.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/packet_context.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/pattern_cards.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/security_adjudication.rs",
    "engine/crates/legion-audit/src/native_providers/reasoning/triggers.rs",
    "engine/crates/legion-audit/src/native_providers/security/adapter.rs",
    "engine/crates/legion-audit/src/native_providers/security/ast_grep.rs",
    "engine/crates/legion-audit/src/native_providers/security/common.rs",
    "engine/crates/legion-audit/src/native_providers/security/container_iac.rs",
    "engine/crates/legion-audit/src/native_providers/security/dependency_osv.rs",
    "engine/crates/legion-audit/src/native_providers/security/history.rs",
    "engine/crates/legion-audit/src/native_providers/security/history_qualification_record.rs",
    "engine/crates/legion-audit/src/native_providers/security/history_qualification_tests.rs",
    "engine/crates/legion-audit/src/native_providers/security/imported_sarif.rs",
    "engine/crates/legion-audit/src/native_providers/security/mod.rs",
    "engine/crates/legion-audit/src/native_providers/security/opengrep.rs",
    "engine/crates/legion-audit/src/native_providers/security/packs.rs",
    "engine/crates/legion-audit/src/native_providers/security/producer.rs",
    "engine/crates/legion-audit/src/native_providers/security/scanner_tools.rs",
    "engine/crates/legion-audit/src/native_providers/security/scanners.rs",
    "engine/crates/legion-audit/src/native_providers/security/secrets.rs",
    "engine/crates/legion-audit/src/native_providers/security/supply_chain.rs",
    "engine/crates/legion-audit/src/native_providers/security/suppressions.rs",
    "engine/crates/legion-audit/src/next.rs",
    "engine/crates/legion-audit/src/normalize.rs",
    "engine/crates/legion-audit/src/p12_pipeline/mod.rs",
    "engine/crates/legion-audit/src/p12_pipeline/store.rs",
    "engine/crates/legion-audit/src/plan.rs",
    "engine/crates/legion-audit/src/report.rs",
    "engine/crates/legion-audit/src/review_runtime/batch.rs",
    "engine/crates/legion-audit/src/review_runtime/cost.rs",
    "engine/crates/legion-audit/src/review_runtime/gather.rs",
    "engine/crates/legion-audit/src/review_runtime/mod.rs",
    "engine/crates/legion-audit/src/review_runtime/model.rs",
    "engine/crates/legion-audit/src/review_runtime/native.rs",
    "engine/crates/legion-audit/src/review_runtime/partial.rs",
    "engine/crates/legion-audit/src/review_runtime/projection.rs",
    "engine/crates/legion-audit/src/review_runtime/tools.rs",
    "engine/crates/legion-audit/src/review_runtime/verification.rs",
    "engine/crates/legion-audit/src/scope.rs",
    "engine/crates/legion-audit/src/snapshot.rs",
    "engine/crates/legion-audit/src/source_cache.rs",
    "engine/crates/legion-audit/src/verify.rs",
    "engine/crates/legion-audit/src/wf_port/mod.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/external_process.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/mod.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/provider_executor.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/provider_registry.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/registry.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/runtime_module.rs",
    "engine/crates/legion-audit/src/wf_port/wf010/tool_identity.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/common.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/complete.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/finalize.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/mod.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/plan.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/run.rs",
    "engine/crates/legion-audit/src/wf_port/wf064/runtime.rs",
    "engine/crates/legion-audit/src/worktree.rs",
    "engine/crates/legion-contracts/Cargo.toml",
    "engine/crates/legion-contracts/src/agent.rs",
    "engine/crates/legion-contracts/src/canonical.rs",
    "engine/crates/legion-contracts/src/enums.rs",
    "engine/crates/legion-contracts/src/host.rs",
    "engine/crates/legion-contracts/src/id.rs",
    "engine/crates/legion-contracts/src/l2_port/enums.rs",
    "engine/crates/legion-contracts/src/l2_port/executable.rs",
    "engine/crates/legion-contracts/src/l2_port/mod.rs",
    "engine/crates/legion-contracts/src/l2_port/schema_names.rs",
    "engine/crates/legion-contracts/src/lib.rs",
    "engine/crates/legion-contracts/src/plan.rs",
    "engine/crates/legion-contracts/src/policy.rs",
    "engine/crates/legion-contracts/src/provider.rs",
    "engine/crates/legion-contracts/src/provider_result.rs",
    "engine/crates/legion-contracts/src/receipt.rs",
    "engine/crates/legion-contracts/src/report.rs",
    "engine/crates/legion-contracts/src/state_root.rs",
    "engine/crates/legion-contracts/src/task.rs",
    "engine/crates/legion-contracts/src/trace.rs",
    "engine/crates/legion-effects/Cargo.toml",
    "engine/crates/legion-effects/src/artifact.rs",
    "engine/crates/legion-effects/src/credential.rs",
    "engine/crates/legion-effects/src/environment.rs",
    "engine/crates/legion-effects/src/error.rs",
    "engine/crates/legion-effects/src/executable.rs",
    "engine/crates/legion-effects/src/executor.rs",
    "engine/crates/legion-effects/src/lib.rs",
    "engine/crates/legion-effects/src/platform.rs",
    "engine/crates/legion-effects/src/receipt.rs",
    "engine/crates/legion-effects/src/request.rs",
    "engine/crates/legion-effects/src/sandbox.rs",
    "engine/crates/legion-effects/src/unix.rs",
    "engine/crates/legion-effects/src/windows.rs",
    "engine/crates/legion-provider-sdk/Cargo.toml",
    "engine/crates/legion-provider-sdk/src/auth.rs",
    "engine/crates/legion-provider-sdk/src/context.rs",
    "engine/crates/legion-provider-sdk/src/coverage.rs",
    "engine/crates/legion-provider-sdk/src/error.rs",
    "engine/crates/legion-provider-sdk/src/external_project_tool.rs",
    "engine/crates/legion-provider-sdk/src/http_client.rs",
    "engine/crates/legion-provider-sdk/src/inference.rs",
    "engine/crates/legion-provider-sdk/src/lib.rs",
    "engine/crates/legion-provider-sdk/src/provider.rs",
    "engine/crates/legion-provider-sdk/src/registry.rs",
    "engine/crates/legion-provider-sdk/src/result.rs",
    "engine/crates/legion-provider-sdk/src/retry.rs",
    "engine/crates/legion-provider-sdk/src/stream.rs",
    "engine/crates/legion-provider-sdk/src/testkit.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/mod.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/canonical.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/contracts.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/dag.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/mod.rs",
    "engine/crates/legion-provider-sdk/src/wf_port/r53/testkit.rs",
    "engine/crates/legion-rules/Cargo.toml",
    "engine/crates/legion-rules/src/compiler.rs",
    "engine/crates/legion-rules/src/error.rs",
    "engine/crates/legion-rules/src/evidence.rs",
    "engine/crates/legion-rules/src/lexical.rs",
    "engine/crates/legion-rules/src/lib.rs",
    "engine/crates/legion-rules/src/schema.rs",
    "engine/crates/legion-rules/src/structural.rs",
    "engine/crates/legion-rules/src/wf_port/mod.rs",
    "engine/crates/legion-rules/src/wf_port/u06/mod.rs",
    "engine/rust-toolchain.toml",
    "scripts/ci/audit-secrets-history-provider-accuracy.py",
]
PINS = {
    "gitleaks_8.30.0_darwin_x64.tar.gz": "sha256:ca221d012d247080c2f6f61f4b7a83bffa2453806b0c195c795bbe9a8c775ed5",
    "gitleaks_8.30.0_darwin_arm64.tar.gz": "sha256:b251ab2bcd4cd8ba9e56ff37698c033ebf38582b477d21ebd86586d927cf87e7",
}
REJECTIONS = {"snapshot-without-manifest", "snapshot-manifest-tamper", "snapshot-inventory-tamper", "history-manifest-tamper",
    "anchor-commit-tamper", "anchor-blobOid-tamper", "anchor-blobDigest-tamper", "anchor-historyManifestDigest-tamper",
    "raw-digest-tamper", "receipt-tamper", "malformed-output", "current-bytes-drift", "selected-pathset-drift",
    "nongit-child-parent-git", "shallow-repository", "missing-object"}
INCOMPLETE = {"nongit-provider", "shallow-provider", "missing-object-provider", "snapshot-provider-without-manifest", "truncated-output"}
TOKEN = "ghp_" + "R7kQ2mZ9xL4vB8nC1dF6hJ3sT5wY0aE2gU9i"

def require(ok, message):
    if not ok:
        raise ValueError(message)

def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "unexpected/missing fields: " + str(expected))

def encoded(value, sort=True):
    return json.dumps(value, sort_keys=sort, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()

def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()

def cdigest(value):
    return digest(encoded(value))

def parsed(raw):
    def pairs(items):
        require(len(dict(items)) == len(items), "duplicate JSON member")
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))

def file(root, name):
    p = PurePosixPath(name)
    require(not p.is_absolute() and p.parts and all(v not in ("", ".", "..") for v in p.parts) and "\\" not in name, "unsafe source path")
    path = root
    for part in p.parts:
        path = path / part
        require(not path.is_symlink(), "symlink in source closure")
    require(path.is_file(), "missing source")
    return path

def unhex(value):
    require(isinstance(value, str) and len(value) % 2 == 0 and re.fullmatch("[0-9a-f]*", value) is not None, "invalid raw hex")
    return bytes.fromhex(value)

def oid(value):
    return isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is not None

def safe_path(value):
    p = PurePosixPath(value)
    return isinstance(value, str) and value and not p.is_absolute() and all(v not in (".", "..") for v in p.parts) and "\\" not in value and "\x00" not in value

def object_store(values):
    require(isinstance(values, dict) and 0 < len(values) <= 1000, "fixture object store missing/oversize")
    out = {}
    for name, item in values.items():
        keys(item, {"kind", "hex", "digest"})
        require(oid(name) and item["kind"] in ("commit", "tree", "blob", "tag"), "invalid Git object identity")
        raw = unhex(item["hex"])
        require(len(raw) <= 8 * 1024 * 1024 and digest(raw) == item["digest"], "Git raw digest differs")
        framed = item["kind"].encode() + b" " + str(len(raw)).encode() + b"\0" + raw
        computed = (hashlib.sha1(framed) if len(name) == 40 else hashlib.sha256(framed)).hexdigest()
        require(name == computed, "Git object OID differs")
        out[name] = (item["kind"], raw)
    return out

def tree_files(store, tree, prefix="", active=None):
    active = set() if active is None else active
    require(tree not in active and tree in store and store[tree][0] == "tree", "missing/cyclic tree")
    raw, offset, files = store[tree][1], 0, {}
    active = active | {tree}
    width = len(bytes.fromhex(tree))
    while offset < len(raw):
        end = raw.find(b"\0", offset)
        require(end > offset and end + 1 + width <= len(raw), "truncated tree")
        mode, name = raw[offset:end].split(b" ", 1)
        name = name.decode("utf-8", "strict")
        path = prefix + name
        require(safe_path(path) and "/" not in name, "unsafe Git tree path")
        child = raw[end + 1:end + 1 + width].hex()
        require(child in store, "missing tree child")
        mode = mode.decode()
        if mode in ("40000", "040000"):
            files.update(tree_files(store, child, path + "/", active))
        else:
            require(mode in ("100644", "100755") and store[child][0] == "blob", "unsupported fixture tree entry")
            require(path not in files, "duplicate Git tree path")
            blob = store[child][1]
            files[path] = {"oid": child, "digest": digest(blob), "mode": mode, "lines": blob.count(b"\n") + 1}
        offset = end + 1 + width
    return files

def commits(store, tips):
    pending, out = list(tips), {}
    while pending:
        name = pending.pop()
        require(oid(name) and name in store, "missing tip/parent")
        if name in out:
            continue
        kind, raw = store[name]
        if kind == "tag":
            target = raw.split(b"\n", 1)[0].decode().removeprefix("object ")
            pending.append(target)
            continue
        require(kind == "commit", "tip not commit")
        headers = raw.split(b"\n\n", 1)[0].decode().splitlines()
        trees = [v[5:] for v in headers if v.startswith("tree ")]
        parents = [v[7:] for v in headers if v.startswith("parent ")]
        require(len(trees) == 1 and len(set(parents)) == len(parents), "malformed commit")
        require(b"Audit synthetic fixture <audit-fixture@example.invalid>" in raw, "unexpected fixture author")
        out[name] = {"parents": parents, "files": tree_files(store, trees[0])}
        pending.extend(parents)
    return out

def complete(result):
    keys(result, {"schema_version", "provider", "applicable", "required", "status", "complete", "coverage", "findings", "coverage_gaps", "degradation", "details"})
    require(result["schema_version"] == 1 and result["provider"] == PROVIDER and result["applicable"] is True and result["required"] is True and result["status"] == "complete" and result["complete"] is True and result["coverage_gaps"] == [] and result["degradation"] == [], "provider incomplete")
    coverage = result["coverage"]
    keys(coverage, {"denominator_digest", "expected", "examined", "gaps"})
    require(type(coverage["expected"]) is int and coverage["expected"] > 0 and coverage["examined"] == coverage["expected"] and coverage["gaps"] == [], "file denominator incomplete")

def sdk(run, scanner):
    keys(run, {"sdk", "projection", "stdoutHex", "stderrHex", "tool", "wrapper"})
    r = run["sdk"]
    keys(r, {"schemaVersion", "receiptId", "requestId", "providerId", "planId", "policyId", "policy", "taskId", "state", "complete", "executable", "command", "cwd", "environmentNames", "sandbox", "processTree", "timing", "exitCode", "signal", "stdout", "stderr", "parser", "gaps"})
    require(r["schemaVersion"] == 1 and r["providerId"] == PROVIDER and r["complete"] is True and r["state"] == "completed" and r["gaps"] == [] and r["signal"] is None, "SDK did not complete")
    p = r["policy"]
    keys(p, {"id", "version", "digest", "allowed", "reason"})
    require(p == {"id":"synthetic-secrets-history-qualification-only", "version":1,"digest":digest(b"synthetic-secrets-history-qualification-only"),"allowed":True,"reason":None}, "constructed policy differs")
    require(r["sandbox"] == {"required":False,"receiptId":None,"networkEnabled":False} and run["wrapper"] is None, "fixture sandbox/wrapper scope differs")
    process = r["processTree"]
    keys(process, {"started", "terminated", "hardKilled", "reaped", "detail"})
    require(process["started"] is True and process["terminated"] is True and process["reaped"] is True and process["hardKilled"] is False, "process lifecycle incomplete")
    require(r["parser"] == {"attempted":False,"succeeded":False,"error":None}, "SDK parser projection differs from raw external execution")
    timing = r["timing"]
    keys(timing, {"startedAtMs", "completedAtMs", "durationMs"})
    require(all(type(v) is int and v >= 0 for v in timing.values()) and timing["completedAtMs"] >= timing["startedAtMs"] and timing["durationMs"] == timing["completedAtMs"] - timing["startedAtMs"], "timing differs")
    executable = r["executable"]
    keys(executable, {"requestedPath", "canonicalPath", "digest", "digestState", "signature", "version"})
    require(executable["canonicalPath"] == scanner["path"] and executable["digest"] == scanner["executableDigest"] and executable["digestState"] == "Sealed", "actual launch is not pinned tool")
    version = executable["version"]
    keys(version, {"args", "output", "exitCode", "qualified", "skippedByPolicy"})
    require(version["qualified"] is True and version["skippedByPolicy"] is False and version["exitCode"] == 0 and re.search(r"(?<![\w.])8\.30\.0(?![\w.])", version["output"] or ""), "actual version probe differs")
    command = r["command"]
    keys(command, {"executable", "args", "environmentNames", "redactedArgumentIndexes", "redactedEnvironmentNames"})
    require(command["executable"] == scanner["path"] and command["redactedArgumentIndexes"] == [] and command["redactedEnvironmentNames"] == [], "command unexpectedly wrapped/redacted")
    require(set(command["environmentNames"]) == set(r["environmentNames"]), "SDK environment projection differs")
    args = command["args"]
    require(isinstance(args, list) and len(args) >= 2 and args[0] in ("dir", "git") and "--exit-code=10" in args and "--ignore-gitleaks-allow" in args and "--log-level=error" in args, "strict scanner argv differs")
    projection = run["projection"]
    require(run["tool"] == {"name":"gitleaks","version":(version["output"] or "").strip().splitlines()[0],"executableDigest":scanner["executableDigest"]}, "tool and launch identities differ")
    for field in ("receiptId", "policyId", "exitCode", "state", "complete", "environmentNames", "sandbox"):
        require(projection[field] == r[field], "reduced/full SDK receipt differs")
    require(projection["argv"] == ["gitleaks"] + args and projection["tool"] == "gitleaks" and projection["version"] == run["tool"]["version"] and projection["executableDigest"] == scanner["executableDigest"] and projection["offline"] is True and projection["evidence"] == "tool", "reduced tool projection differs")
    streams = []
    for label in ("stdout", "stderr"):
        raw = unhex(run[label + "Hex"])
        artifact = r[label]
        keys(artifact, {"path", "digest", "bytes", "immutable"})
        require(artifact["digest"] == digest(raw) and artifact["bytes"] == len(raw) and artifact["immutable"] is True and artifact["path"] == r["requestId"] + "/" + label, "raw artifact/request binding differs")
        require(projection[label + "Digest"] == artifact["digest"] and projection[label + "Bytes"] == len(raw), "reduced/raw receipt differs")
        streams.append(raw)
    require(streams[1] == b"", "scanner stderr prevents complete source proof")
    report = parsed(streams[0])
    require(isinstance(report, list) and r["exitCode"] == (10 if report else 0), "strict report/exit contract differs")
    for finding in report:
        require(isinstance(finding, dict) and isinstance(finding.get("RuleID"), str) and finding["RuleID"] and type(finding.get("StartLine")) is int and finding["StartLine"] > 0 and type(finding.get("EndLine")) is int and finding["EndLine"] >= finding["StartLine"], "malformed finding")
    return args, report

def validate_final_findings(result, rows):
    """Bind final FindingRef IDs to native normalized rows & exact evidence.

    A normalized analysis row alone never qualifies finding-stage delivery.
    Historical anchors were already checked against native raw output & Git.
    """
    refs, evidence, locations, titles, messages = [], {}, {}, {}, {}
    for finding in rows:
        path, line, rule = finding["file"], finding["line"], finding["ruleId"]
        excerpt = finding["secretDigest"]
        require(isinstance(rule,str) and rule and re.fullmatch(r"sha256:[0-9a-f]{64}",excerpt or ""), "final finding lacks source digest/rule")
        identity = "\0".join((PROVIDER,rule,path,str(line),excerpt))
        historical = finding["mode"] == "history"
        if historical:
            identity += "\0history\0" + finding["commit"]
        finding_id = digest(identity.encode())
        if finding_id in evidence:
            continue
        refs.append({"id":finding_id,"severity":finding.get("severity","warning")})
        proof = {"provider":PROVIDER,"ruleId":rule,"path":path,"line":line,"excerptDigest":excerpt,"redacted":True}
        if historical:
            proof.update({field:finding[field] for field in ("commit","mode","blobOid","blobDigest","historyManifestDigest")})
        evidence[finding_id] = proof
        locations[finding_id] = [path + ":" + str(line)]
        titles[finding_id] = rule
        messages[finding_id] = PROVIDER + " reported " + rule + " at " + path + ":" + str(line)
    require(result["findings"] == refs, "final findings differ from native normalized/evidenced findings")
    details = result["details"]
    for key,wanted in (("findingEvidence",evidence),("findingLocations",locations),("findingTitles",titles),("findingMessages",messages)):
        require(details.get(key,{}) == wanted, "final finding evidence map differs: " + key)
    require(details.get("candidates",[]) == [], "fixture findings demoted instead of delivered")


def validate_case(case, scanner, snapshot=False):
    keys(case, {"root", "inventory", "providerSpec", "files", "manifest", "objects", "result", "runs"})
    result, proof = case["result"], case["manifest"]
    require(result["details"]["analysis"]["historyProof"] == proof, "retained manifest differs from actual provider result")
    complete(result)
    keys(proof, {"digest", "manifest"})
    m = proof["manifest"]
    # Production manifest uses serialized struct insertion order; record envelope
    # uses canonical sorted JSON. These are separate explicit digest domains.
    require(proof["digest"] == digest(encoded(m, sort=False)), "native manifest digest differs")
    require(m["schemaVersion"] == 1 and m["shallow"] is False and m["executionRoot"] == case["root"], "manifest root/state differs")
    require(m["historySelection"] == ("snapshot-scope" if snapshot else "repository"), "history selection differs")
    require((m["snapshotDigest"] is not None and m["scopeDigest"] is not None) == snapshot, "snapshot binding differs")
    inv = case["inventory"]
    require(m["inventoryDigest"] == inv["digest"] and result["coverage"]["denominator_digest"] == case["providerSpec"]["configuration"]["denominatorDigest"], "inventory/spec/result denominator differs")
    files = {p: unhex(v) for p,v in case["files"].items()}
    require(all(safe_path(p) for p in files) and m["current"] == {p:digest(v) for p,v in files.items()}, "current selected bytes differ")
    entries = inv["entries"]
    require(inv["schemaVersion"] == 1 and inv["repositoryId"] == m["repositoryId"] == "synthetic-history-qualification" and inv["generation"] == "filesystem:" + cdigest(entries) and inv["digest"] == cdigest([1,inv["repositoryId"],inv["generation"],entries]), "frozen inventory digest differs")
    expected_spec = {"id":PROVIDER,"version":"1.0.0","role":"security","phase":"source","lensIds":[],"dependencies":[],"kind":"typed-external-project-tool","configuration":{"selector":{"op":"always"},"denominatorDigest":inv["digest"],"denominatorCount":len(entries)},"bounds":{},"cleanClaim":"evidence-only","benchmarkStatus":"not-required","benchmarkRequiredForCleanClaim":False,"qualificationDigest":None,"required":True}
    require(case["providerSpec"] == expected_spec, "actual constructed provider spec differs")
    require({e["path"]:e["digest"] for e in entries} == m["current"] and len(entries) == len(files) == result["coverage"]["expected"], "frozen file denominator differs")
    store = object_store(case["objects"])
    graph = commits(store, m["tips"])
    require(graph == m["commits"] and m["head"] in store, "captured ancestry/path/blob manifest differs")
    require(all(oid(v) and v in store for v in m["refs"].values()) and m["tips"], "ref map missing objects")
    if not snapshot:
        # Fixture refs point directly at commits; detached HEAD included exactly.
        require(set(m["tips"]) == set(m["refs"].values()) | {m["head"]}, "tip/ref capture differs")
        require(m["sourceRoot"] == m["objectRoot"] == case["root"], "direct source root differs")
    require(len(case["runs"]) == 2, "two SDK passes required")
    passes = [sdk(r, scanner) for r in case["runs"]]
    require([p[0][0] for p in passes] == ["dir", "git"], "current/history pass ordering differs")
    require(len({r["sdk"]["requestId"] for r in case["runs"]}) == 2, "passes share request identity")
    for run in case["runs"]:
        r = run["sdk"]
        # Source-bound shared adapter hashes producer ID + time/sequence into the
        # artifact namespace; its nonce preimage is not retained in SDK receipts.
        request_id = r["requestId"]
        require(isinstance(request_id, str) and re.fullmatch(r"legion-audit/[0-9a-f]{64}", request_id) is not None
                and r["planId"] == inv["digest"] and r["taskId"] == "gitleaks"
                and r["receiptId"] == "receipt:" + request_id, "SDK request/plan/receipt binding differs")
    history_args = passes[1][0]
    log_opts = [v for v in history_args if v.startswith("--log-opts=")]
    require(len(log_opts) == 1 and {"--text", "--no-show-signature", "--no-ext-diff", "--no-textconv", "--no-renames"}.issubset(set(log_opts[0].split())) and set(m["tips"]).issubset(set(log_opts[0].split())) and history_args[1] == m["objectRoot"], "scanner captured tips/source differ")
    rows = result["details"]["analysis"]["findings"]
    for finding in rows:
        path, line = finding["file"], finding["line"]
        require(safe_path(path) and type(line) is int and line > 0, "invalid normalized anchor")
        if finding["mode"] == "history":
            commit = finding["commit"]
            require(commit in graph and path in graph[commit]["files"], "historical anchor not reachable")
            blob = graph[commit]["files"][path]
            require(finding["blobOid"] == blob["oid"] and finding["blobDigest"] == blob["digest"] and finding["historyManifestDigest"] == proof["digest"] and line <= blob["lines"], "historical anchor blob differs")
            require(any(v.get("Commit") == commit and (v.get("File") == path or str(v.get("File", "")).endswith("/" + path)) and v["StartLine"] == line for v in passes[1][1]), "normalized history finding missing raw native finding")
        else:
            require(finding["mode"] == "current" and finding["commit"] is None and path in files and line <= len(files[path].splitlines()), "current anchor differs")
            require(any((v.get("File") == path or str(v.get("File", "")).endswith("/" + path)) and v["StartLine"] == line for v in passes[0][1]), "normalized current finding missing raw native finding")
    require(len(rows) == sum(len(report) for _,report in passes), "raw/normalized finding count differs")
    validate_final_findings(result, rows)
    require(TOKEN not in encoded(result).decode(), "normalized result leaked synthetic secret")
    return rows, graph, files

def snapshot_files(manifest, store, selected_files):
    """Replay selected + deleted changed base files through retained Git objects."""
    scope = manifest["scope"]
    require(scope["spec"] == {"kind":"committed"} and scope["changedPaths"] == ["deleted.txt"], "snapshot fixture scope differs")
    sides = {}
    for side, entries_name in (("files", "selectedEntries"), ("baseFiles", "baselineEntries")):
        rows, entries = manifest[side], scope[entries_name]
        require(set(rows) == set(entries), "snapshot file/entry path set differs")
        files = {}
        for path, metadata in rows.items():
            require(safe_path(path), "snapshot file path unsafe")
            entry = entries[path]
            keys(entry, {"mode", "oid"})
            require(entry["mode"] in ("100644", "100755") and entry["oid"] in store
                    and store[entry["oid"]][0] == "blob", "snapshot file object differs")
            body = store[entry["oid"]][1]
            require(metadata == {"digest":digest(body), "bytes":len(body), "mode":entry["mode"]}, "snapshot file seal differs")
            files[path] = body
        sides[side] = files
    require(sides["files"] == selected_files, "snapshot selected source differs")
    require(sides["baseFiles"] == {**selected_files, "deleted.txt":('token = "' + TOKEN + '"\n').encode()},
            "snapshot deleted baseline source differs")
    files = dict(sides["files"])
    for path in scope["changedPaths"]:
        if path not in files and path in sides["baseFiles"]:
            files[path] = sides["baseFiles"][path]
    return files


def validate_record(root, row, live=False):
    root = Path(root).resolve()
    keys(row, {"schema", "family", "provider", "stage", "status", "claimScope", "productionQualification", "installedCliAdmission", "admissionScope", "modelCalls", "harness", "repositoryRoot", "evidenceRoot", "sources", "scanner", "cases", "controls", "snapshot", "signature", "qualificationDigest"})
    require(row["schema"] == "legion-secrets-history-native-qualification/1" and row["family"] == "secrets-history" and row["provider"] == PROVIDER and row["stage"] == "finding" and row["status"] == "pass", "record identity differs")
    require(row["claimScope"] == "known-answer-fixture-cases" and row["productionQualification"] is False and row["installedCliAdmission"] is False and row["admissionScope"] == "explicit constructed SDK authorizer; sandbox disabled in synthetic fixture only" and type(row["modelCalls"]) is int and row["modelCalls"] == 0 and row["harness"] == SELECTOR, "fixture admission/claim differs")
    require(row["qualificationDigest"] == cdigest({k:v for k,v in row.items() if k != "qualificationDigest"}), "qualification canonical digest differs")
    sources = row["sources"]
    keys(sources, {"files", "digest", "providerSpec", "providerSpecDigest"})
    wanted = {name:digest(file(root,name).read_bytes()) for name in SOURCES}
    require(sources["files"] == wanted and sources["digest"] == cdigest(wanted), "source closure differs")
    registry = parsed(file(root,"src/registry/providers.json").read_bytes())["providers"]
    specs = [p for p in registry if p["id"] == PROVIDER]
    require(len(specs) == 1, "fixed provider missing/duplicate")
    spec = {k:v for k,v in specs[0].items() if k != "benchmark"}
    require(sources["providerSpec"] == spec and sources["providerSpecDigest"] == cdigest(spec), "production spec binding differs")
    scanner = row["scanner"]
    keys(scanner, {"version", "path", "executableDigest", "archiveName", "archiveDigest"})
    require(scanner["version"] == "8.30.0" and PINS.get(scanner["archiveName"]) == scanner["archiveDigest"] and re.fullmatch(r"sha256:[0-9a-f]{64}", scanner["executableDigest"] or ""), "official native scanner pin differs")
    if live:
        require(str(root) == row["repositoryRoot"], "live source root differs")
        tool = Path(scanner["path"])
        require(tool.is_absolute() and tool.is_file() and not tool.is_symlink() and digest(tool.read_bytes()) == scanner["executableDigest"], "live pinned tool differs")
    keys(row["cases"], {"planted", "clean", "current", "attributes-signature"})
    verified = {name:validate_case(case,scanner) for name,case in row["cases"].items()}
    planted, clean, current = [verified[name] for name in ("planted", "clean", "current")]
    require(planted[2] == clean[2] == {"README.md":b"synthetic qualification fixture\n"} and clean[0] == [], "matched clean/current-tree control differs")
    for path in ("deleted.txt", "branch-only.txt"):
        found = [v for v in planted[0] if v["file"] == path and v["mode"] == "history"]
        require(found and any(TOKEN.encode() in object_store(row["cases"]["planted"]["objects"])[v["blobOid"]][1] for v in found), "planted historical secret not detected")
    m = row["cases"]["planted"]["manifest"]["manifest"]
    main = commits(object_store(row["cases"]["planted"]["objects"]), [m["head"]])
    require(any(v["file"] == "branch-only.txt" and v["commit"] not in main for v in planted[0]), "branch-only control did not prove non-HEAD history")
    require(any(v["file"] == "current.txt" and v["mode"] == "current" for v in current[0]) and TOKEN.encode() in current[2]["current.txt"], "current secret control missing")
    attributes = verified["attributes-signature"]
    require(attributes[2].get(".gitattributes") == b"*.txt -diff\n" and any(v["file"] == "deleted.txt" and v["mode"] == "history" for v in attributes[0]), "binary attribute coverage missing")
    signature = row["signature"]
    keys(signature, {"signedTip", "logShowSignature", "gpgProgram", "verifierDigest", "markerExists"})
    attr_store = object_store(row["cases"]["attributes-signature"]["objects"])
    require(signature["signedTip"] in attr_store and b"\ngpgsig -----BEGIN PGP SIGNATURE-----" in attr_store[signature["signedTip"]][1] and signature["logShowSignature"] == "true" and signature["markerExists"] is False, "hostile verifier control not observed")
    require(signature["gpgProgram"].endswith("/forbidden-gpg") and re.fullmatch(r"sha256:[0-9a-f]{64}", signature["verifierDigest"] or ""), "verifier fixture missing")
    snapshot = row["snapshot"]
    keys(snapshot, {"case", "manifestHex", "manifestPath", "manifestDigest", "selectedOid", "excludedBranch"})
    raw_manifest = unhex(snapshot["manifestHex"])
    require(digest(raw_manifest) == snapshot["manifestDigest"], "retained snapshot raw digest differs")
    snapshot_manifest = parsed(raw_manifest)
    _, _, sf = validate_case(snapshot["case"],scanner, snapshot=True)
    sm = snapshot["case"]["manifest"]["manifest"]
    require(sm["snapshotDigest"] == digest(encoded(snapshot_manifest, sort=False)) and sm["scopeDigest"] == digest(encoded(snapshot_manifest["scope"], sort=False)) and snapshot["selectedOid"] == sm["selectedOid"] and snapshot["excludedBranch"] not in sm["tips"] and sf == snapshot_files(snapshot_manifest, object_store(snapshot["case"]["objects"]), planted[2]), "snapshot scope/source binding differs")
    # Raw manifest is authenticated separately from public per-case history proof.
    require(snapshot_manifest["executionRoot"] == sm["executionRoot"] and snapshot_manifest["scope"]["sourceRoot"] == sm["sourceRoot"], "snapshot original source differs")
    keys(row["controls"], REJECTIONS | INCOMPLETE)
    for name,item in row["controls"].items():
        if name in REJECTIONS:
            require(item.get("observed") == "rejected" and (isinstance(item.get("error"),str) and bool(item["error"]) or item.get("predicate") is False), "native rejection observation absent")
        else:
            require(item.get("observed") == "incomplete" and item["result"]["complete"] is False and (item["result"]["coverage_gaps"] or item["result"]["coverage"] is None or item["result"]["coverage"]["gaps"]), "native incomplete observation absent")
    controls = row["controls"]
    tampered = controls["history-manifest-tamper"]["input"]
    require(tampered["digest"] != digest(encoded(tampered["manifest"], sort=False)), "native manifest tamper witness absent")
    for field in ("commit", "blobOid", "blobDigest", "historyManifestDigest"):
        require(controls["anchor-" + field + "-tamper"]["input"][field] == "tampered", "anchor tamper witness absent")
    for name in ("raw-digest-tamper", "receipt-tamper", "malformed-output"):
        rejected = False
        try:
            sdk(controls[name]["input"],scanner)
        except (ValueError, KeyError, TypeError, IndexError):
            rejected = True
        require(rejected, "tampered retained SDK/raw proof passed independent validator")
    return {"provider":PROVIDER,"family":"secrets-history","stage":"finding","scope":"known-answer-fixture-cases","status":"pass","productionQualification":False,"installedCliAdmission":False,"qualificationDigest":row["qualificationDigest"],"sourceDigest":sources["digest"],"scannerDigest":scanner["executableDigest"],"modelCalls":0}

def validate_negative_mutations(root, original):
    """Use genuine native record as control; reseal envelope after every mutation.

    Independent semantic rejection must remain after its outer checksum changes.
    These controls never manufacture an accepted record or replace native cases.
    """
    def manifest(row):
        case = row["cases"]["planted"]
        case["manifest"]["manifest"]["head"] = "0" * 40
        case["manifest"]["digest"] = digest(encoded(case["manifest"]["manifest"], sort=False))
        case["result"]["details"]["analysis"]["historyProof"] = copy.deepcopy(case["manifest"])
    def blob(row):
        store = row["cases"]["planted"]["objects"]
        item = next(value for value in store.values() if value["kind"] == "blob")
        raw = unhex(item["hex"]) + b"tampered"
        item.update(hex=raw.hex(), digest=digest(raw))
    def commit(row):
        store = row["cases"]["planted"]["objects"]
        item = next(value for value in store.values() if value["kind"] == "commit")
        raw = unhex(item["hex"]) + b"tampered"
        item.update(hex=raw.hex(), digest=digest(raw))
    def report(row):
        run = row["cases"]["planted"]["runs"][1]
        raw = b"{"
        run["stdoutHex"] = raw.hex()
        run["sdk"]["stdout"].update(digest=digest(raw),bytes=len(raw))
        run["projection"].update(stdoutDigest=digest(raw),stdoutBytes=len(raw))
    mutations = {
        "source": lambda r:r["sources"]["files"].update({SOURCES[0]:digest(b"tampered")}),
        "spec": lambda r:r["sources"]["providerSpec"].update(id="tampered"),
        "fixture": lambda r:r["cases"]["clean"]["files"].update({"README.md":b"tampered".hex()}),
        "manifest": manifest,
        "pathset": lambda r:r["cases"]["planted"]["manifest"]["manifest"]["current"].update({"outside.txt":digest(b"tampered")}),
        "commit": commit, "blob":blob,
        "receipt": lambda r:r["cases"]["planted"]["runs"][0]["sdk"].update(complete=False),
        "raw-digest": lambda r:r["cases"]["planted"]["runs"][0].update(stdoutHex="20"),
        "truncated-report":report,
        "scanner-pin": lambda r:r["scanner"].update(archiveDigest=digest(b"tampered")),
        "snapshot": lambda r:r["snapshot"].update(manifestHex="7b"),
        "required-control":lambda r:r["controls"].pop("missing-object"),
        "claim":lambda r:r.update(productionQualification=True),
        "empty-final-findings":lambda r:r["cases"]["planted"]["result"].update(findings=[]),
        "final-finding-id":lambda r:r["cases"]["planted"]["result"]["findings"][0].update(id=digest(b"tampered")),
        "missing-final-evidence":lambda r:r["cases"]["planted"]["result"]["details"].update(findingEvidence={}),
        "missing-final-location":lambda r:r["cases"]["planted"]["result"]["details"].update(findingLocations={}),
        "final-evidence-commit":lambda r:next(iter(r["cases"]["planted"]["result"]["details"]["findingEvidence"].values())).update(commit="tampered"),
    }
    for name, mutation in mutations.items():
        changed = copy.deepcopy(original)
        mutation(changed)
        changed["qualificationDigest"] = cdigest({k:v for k,v in changed.items() if k != "qualificationDigest"})
        rejected = False
        try:
            validate_record(root,changed,live=False)
        except (ValueError, KeyError, TypeError, IndexError):
            rejected = True
        require(rejected,"native record negative mutation accepted: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--receipts",type=Path,required=True)
    args = parser.parse_args()
    path = args.receipts / (PROVIDER + ".json")
    require(path.is_file() and not path.is_symlink(), "native qualification record absent")
    row = parsed(path.read_bytes())
    require(Path(row["evidenceRoot"]).resolve() == args.receipts.resolve(), "live evidence root differs")
    result = validate_record(args.root,row,live=True)
    validate_negative_mutations(args.root,row)
    print("SECRETS_HISTORY_NATIVE_QUALIFICATION_SUMMARY " + encoded({"records":[result],"modelCalls":0}).decode())

if __name__ == "__main__":
    main()
