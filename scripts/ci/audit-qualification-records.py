#!/usr/bin/env python3
"""Offline registration gate; never imports records, promotes, invokes tools, or authenticates CI.

Maintainers must first retrieve CI evidence through authenticated GitHub access &
commit a separate verification object. Its source ownership is the trust boundary;
a run number, record assertion, or this checksum check is not authentication.
Initial registrations accept complete file-only records; external execution
records require a separate extension with archived native receipt validation.
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
VERIFY_VERSION = "legion-provider-accuracy-provenance-verification/1"
BENCH = {"legacy.security.secrets": "secret", "legacy.security.node-dependencies": "dependency_cve",
         "legacy.quality.dead-code": "dead_code", "legacy.quality.duplication": "duplication", "legacy.quality.types": "type_error"}
VALIDATOR = "scripts/ci/audit-provider-accuracy.py"
ENTRY_KEYS = {"provider", "family", "record", "stage", "scope", "sourceClosure", "provenance", "provenanceVerification"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


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


def closure_paths(root, entry):
    require(entry["family"] == "file", "external qualification registration unsupported")
    paths = {GATE, TEST, SCHEMA, ".github/workflows/ci.yml", "scripts/ci/right-git-ci.sh", VALIDATOR, "bench/provider-accuracy-plan.json"}
    paths.update(plan_for(root, entry["provider"])["fixtures"])
    return sorted(paths)


def source_closure(root, entry):
    keys(entry["sourceClosure"], {"sources", "digest"})
    wanted = {path: digest(relative_file(root, path).read_bytes()) for path in closure_paths(root, entry)}
    same(entry["sourceClosure"]["sources"], wanted, "source closure stale/incomplete")
    require(entry["sourceClosure"]["digest"] == digest(encoded(wanted)), "source closure digest differs")


def log_evidence(log, row, validated):
    emissions, summaries = [], []
    for line in log.read_text(encoding="utf-8").splitlines():
        for prefix, collection in (("FILE_PROVIDER_ACCURACY ", emissions), ("FILE_PROVIDER_ACCURACY_SUMMARY ", summaries)):
            position = line.find(prefix)
            if position >= 0:
                collection.append(parsed(line[position + len(prefix):], log))
    originals = [value for value in emissions if value["provider"] == row["provider"]]
    require(len(originals) == 1, "CI log missing/duplicate original record emission")
    same(originals[0], row, "CI log original record differs")
    successful = [value for value in summaries if row["provider"] in value]
    require(len(successful) == 1, "CI log missing/duplicate successful validator summary")
    same(successful[0][row["provider"]], validated, "CI validator summary differs from validated record")
    return digest(encoded(successful[0]))


def provenance(root, entry, row, validated):
    proof, record = entry["provenance"], entry["record"]
    keys(proof, {"repository", "runId", "runAttempt", "jobId", "jobName", "workflow", "commit", "platform", "command", "validator", "log"})
    require(proof["repository"] == "Orthic-Labs/legion" and proof["workflow"] == ".github/workflows/ci.yml"
            and all(type(proof[key]) is int and proof[key] > 0 for key in ("runId", "runAttempt", "jobId"))
            and re.fullmatch(r"[0-9a-f]{40}", proof["commit"] or "") and proof["platform"] in ("macos-15", "windows-2025"), "CI provenance identity differs")
    require(isinstance(proof["jobName"], str) and 0 < len(proof["jobName"]) <= 200, "CI job missing")
    keys(proof["command"], {"harness", "validator"})
    validator = VALIDATOR
    for args in proof["command"].values():
        require(isinstance(args, list) and 0 < len(args) <= 100 and all(isinstance(arg, str) and 0 < len(arg) <= 4096 for arg in args), "CI command missing")
    require(proof["command"]["validator"][:2] == ["python3", validator] and "--root" in proof["command"]["validator"], "CI validator command differs")
    keys(proof["validator"], {"path", "sha256"})
    require(proof["validator"] == {"path": validator, "sha256": digest(relative_file(root, validator).read_bytes())}, "CI validator stale")
    log = reference(root, proof["log"], "logs")
    summary_digest = log_evidence(log, row, validated)
    verified_path = reference(root, entry["provenanceVerification"], "verification")
    verified = load(verified_path)
    expected = {"schema": VERIFY_VERSION, "method": "authenticated-github-retrieval", "verified": True,
                "repository": proof["repository"], "runId": proof["runId"], "runAttempt": proof["runAttempt"], "jobId": proof["jobId"],
                "workflow": proof["workflow"], "commit": proof["commit"], "conclusion": "success", "recordSha256": record["sha256"],
                "provenanceDigest": digest(encoded(proof)), "logSha256": proof["log"]["sha256"], "validatorSha256": proof["validator"]["sha256"],
                "sourceClosureDigest": entry["sourceClosure"]["digest"], "summaryDigest": summary_digest}
    # This maintainer-owned attestation is required even when every CI id exists.
    # Root populates it only after authenticated retrieval; the gate creates none.
    same(verified, expected, "missing/unverified/source-unbound authenticated CI retrieval")
    return {proof["log"]["path"], entry["provenanceVerification"]["path"]}


def record_binding(root, entry, path):
    provider = entry["provider"]
    plan = plan_for(root, provider)
    require(entry["stage"] == plan["stage"], "file stage differs from source plan")
    return helper("audit-provider-accuracy.py")["validate"](root, path.parent, {provider: plan})[provider]


def controls(row, entry):
    stage = entry["stage"]
    require(row["provider"] == entry["provider"] and row["stage"] == stage and row["status"] == "pass"
            and row["coverageState"] == "complete" and type(row["modelCalls"]) is int and row["modelCalls"] == 0, "record incomplete/failed")
    require(row.get("coverageGaps", []) == [], "record has coverage gaps")
    require(row["qualificationEligible"] is True, "record ineligible")
    # Existing file validator checks typed fact/outcome/candidate controls.


def qualification(entry):
    return {"basis": "retained-provider-accuracy", "index": INDEX, "record": entry["record"]["path"],
            "recordSha256": entry["record"]["sha256"], "originalQualificationDigest": entry["record"]["qualificationDigest"],
            "stage": entry["stage"], "scope": entry["scope"]}


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
        require(entry["provider"] in specs and entry["provider"] not in entries and entry["provider"] not in BENCH, "unexpected/duplicate index provider")
        entries[entry["provider"]] = entry
    retained = {INDEX, SCHEMA}
    for provider, entry in entries.items():
        require(entry["stage"] in ("candidate", "finding", "fact-output", "outcome") and isinstance(entry["scope"], str) and 0 < len(entry["scope"]) <= 1000, "missing corpus claim/stage")
        source_closure(root, entry)
        path = reference(root, entry["record"], "records", original=True)
        require(path.parent.name == provider, "record directory must name provider")
        row = load(path)
        require(entry["record"]["encoding"] == "canonical-json", "original digest encoding differs")
        claimed = row.pop("qualificationDigest")
        require(claimed == entry["record"]["qualificationDigest"] == digest(encoded(row)), "original qualification digest changed")
        row["qualificationDigest"] = claimed
        controls(row, entry)
        require(row["scope"] == entry["scope"], "corpus claim differs from original")
        validated = record_binding(root, entry, path)
        retained.add(entry["record"]["path"])
        retained.update(provenance(root, entry, row, validated))
        benchmark = specs[provider]["benchmark"]
        require(benchmark["status"] == "qualified", "indexed provider not registered")
        same(benchmark["qualification"], qualification(entry), "registry qualification reference differs")
        require(benchmark["qualificationDigest"] == digest(encoded(benchmark["qualification"])), "registry qualification digest differs")
    for provider in registry:
        benchmark, name = provider["benchmark"], provider["id"]
        require(type(benchmark["requiredForCleanClaim"]) is bool, "clean-claim requirement must remain boolean")
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
    return {"registeredRecords": len(entries), "legacyBenchRecords": sum(row["id"] in BENCH for row in registry), "promotions": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--check", action="store_true", required=True)
    args = parser.parse_args()
    print("QUALIFICATION_RECORDS_SUMMARY " + json.dumps(check(args.root), sort_keys=True, separators=(",", ":")))
