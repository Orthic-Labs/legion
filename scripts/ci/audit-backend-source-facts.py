#!/usr/bin/env python3
"""Strict replay of retained backend source facts; never authenticates CI or qualifies runtime/auth."""
import argparse
import copy
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

ID = "framework.backend"
FAMILY = "backend-source-facts"
SCHEMA = "legion-backend-source-facts/1"
SCOPE = "exact thirteen named literal backend source-fact controls; runtime, mount composition & auth remain unproven"
HARNESS = "engine/crates/legion-audit/tests/backend_source_facts.rs"
CORPUS = "scripts/ci/fixtures/audit-backend-source/corpus.json"
VALIDATOR = "scripts/ci/audit-backend-source-facts.py"
FRAMEWORKS = "express fastify nest django fastapi flask spring ktor aspnet rails laravel go-router rust-web".split()
CONTROLS = [name + "-" + control for name in FRAMEWORKS for control in ("positive", "absence", "missing-manifest", "drift")]
CONTROLS += [name + "-unsupported" for name in ("spring", "ktor", "aspnet", "rails", "laravel")]
CONTROLS += ["rails-quoted-decoy", "laravel-quoted-decoy", "express-route-cap"]
CRATES = ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")
SOURCE_ROOTS = ["engine/crates/" + name + "/src" for name in CRATES] + ["src/registry/rules", "src/registry/controls"]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HARNESS, CORPUS, VALIDATOR,
    "scripts/ci/tests/test_audit_backend_source_facts.py", "scripts/ci/audit-qualification-records.py",
    "scripts/ci/tests/test_audit_qualification_records.py", "qualification/provider-accuracy/schema.json",
    "scripts/ci/right-git-ci.sh", ".github/workflows/ci.yml"] + ["engine/crates/" + name + "/Cargo.toml" for name in CRATES]
FALSE_CLAIMS = ("productionQualification", "wholeProviderQualified", "auditCleanClaim", "runtimeQualified", "authQualified", "certificationClaim")
KEY = b"backend-source-known-answer-frozen-plan"
POLICY = {"externalProcesses": "owner-admission-required", "admissionStatus": "unavailable", "effectiveMode": "deny-external"}
RECORD_KEYS = {"schema", "provider", "providerVersion", "family", "stage", "scope", "executionPath", "status", "qualificationEligible",
    "coverageState", "modelCalls", "runtimeExamined", "frameworkDenominator", "controls", "binding", "rawStream", "retainedRoot", "metrics", "qualificationDigest", *FALSE_CLAIMS}
OBSERVATION_KEYS = {"caseId", "framework", "control", "fixtureRoot", "fixtureFiles", "postFreezeFiles", "inventory", "frozenPlan", "planDigest", "planSignature", "nativeResult", "dispatch"}


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def same(value, wanted, message):
    require(encoded(value) == encoded(wanted), message)


def keys(value, wanted):
    require(type(value) is dict and set(value) == set(wanted), "unknown/missing object fields")


def parsed(raw):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def source(root, relative):
    path = PurePosixPath(relative)
    require(type(relative) is str and relative and not path.is_absolute() and str(path) == relative
            and ".." not in path.parts and "\\" not in relative, "unsafe relative source path")
    actual = Path(root)
    require(not actual.is_symlink(), "source root symlink")
    for part in path.parts:
        actual /= part
        require(not actual.is_symlink(), "source ancestor symlink")
    require(actual.is_file(), "source missing: " + relative)
    return actual


def source_files(root):
    files = set(SOURCE_FILES)
    for relative in SOURCE_ROOTS:
        directory = Path(root) / relative
        require(directory.is_dir() and not directory.is_symlink(), "source root missing/unsafe")
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "source closure symlink")
            name = path.relative_to(root).as_posix()
            generated = re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", name)
            if path.is_file() and not generated:
                files.add(name)
    for relative in files:
        source(root, relative)
    return sorted(files)


def contract(root):
    value = parsed(source(root, CORPUS).read_bytes())
    keys(value, {"schemaVersion", "provider", "frameworkDenominator", "scope", "frameworks", "controls", "extraControls"})
    same(value["frameworkDenominator"], FRAMEWORKS, "original thirteen framework denominator differs")
    same(value["controls"], ["positive", "absence", "missing-manifest", "drift"], "fixed controls narrowed")
    same(value["extraControls"], CONTROLS[52:], "lexical/cap controls narrowed")
    require(value["schemaVersion"] == 1 and value["provider"] == ID and len(value["frameworks"]) == 13, "source corpus identity differs")
    same([row["framework"] for row in value["frameworks"]], FRAMEWORKS, "framework rows missing/duplicated/reordered")
    for row in value["frameworks"]:
        expected = {"framework", "manifest", "source", "routes", "decoy"}
        if row["framework"] in ("spring", "ktor", "aspnet", "rails", "laravel"):
            expected.add("unsupported")
        if row["framework"] in ("rails", "laravel"):
            expected.add("quotedDecoy")
        keys(row, expected)
        keys(row["manifest"], {"path", "body", "inventoryDependencies", "sourceFile"})
        keys(row["source"], {"path", "body"})
        require(len(row["routes"]) == 2 and row["decoy"].strip(), "positive/real nonempty absence control missing")
        for route in row["routes"]:
            keys(route, {"method", "path", "file", "line", "auth"})
            require(route["file"] == row["source"]["path"] and type(route["line"]) is int
                    and route["line"] > 0 and route["auth"] == "unknown", "route source/auth contract changed")
    return value


def fixed_case(corpus, case_id):
    # Resolve exact source-owned case sequence, never caller-authored expected output.
    require(case_id in CONTROLS, "unknown source control")
    row = next(row for row in corpus["frameworks"] if case_id.startswith(row["framework"] + "-"))
    control = case_id[len(row["framework"]) + 1:]
    body = row["source"]["body"]
    if control == "absence":
        body = row["decoy"]
    elif control == "unsupported":
        body = row["unsupported"]
    elif control == "quoted-decoy":
        body = row["quotedDecoy"]
    elif control == "route-cap":
        body = "".join("app.get('/r%d', handler);\n" % i for i in range(2001))
    files = {row["source"]["path"]: body}
    if control != "missing-manifest":
        files[row["manifest"]["path"]] = row["manifest"]["body"]
    after = dict(files)
    if control == "drift":
        after[row["source"]["path"]] = "changed after frozen inventory\n"
    return row, control, files, after


def expected_inventory(case_id, row, files):
    entries = []
    for path, text in sorted(files.items()):
        manifest = path == row["manifest"]["path"]
        entries.append({"path": path, "sourceFile": row["manifest"]["sourceFile"] if manifest else True,
            "symbols": [], "dependencies": row["manifest"]["inventoryDependencies"] if manifest else [],
            "packageScripts": [], "digest": digest(text.encode())})
    generation = "filesystem:" + digest(encoded(entries))
    return {"schemaVersion": 1, "repositoryId": case_id, "generation": generation, "entries": entries,
            "digest": digest(encoded([1, case_id, generation, entries]))}


def expected_plan(spec, inventory, benchmark):
    entries = inventory["entries"]
    same(spec["selector"], {"op": "always"}, "original always selector differs")
    denominator = inventory["digest"]
    fields = ("schemaVersion", "family", "consumes", "produces", "selector", "denominatorKind", "runner", "hostCapabilities",
              "execution", "reasoning", "controlIds", "scopes", "selectable")
    configuration = {key: spec[key] for key in fields}
    configuration.update(benchmark=benchmark, runnerClass="rust-algorithm", denominatorDigest=denominator,
                         denominatorCount=len(entries), sourceSides={})
    required = spec["execution"].get("required", True)
    provider = {"id": ID, "version": spec["providerVersion"], "role": spec["role"], "phase": spec["phase"],
        "lensIds": sorted(set(spec["lensIds"])), "dependencies": spec["dependsOn"], "kind": "rust-algorithm",
        "configuration": configuration, "bounds": {"required": required, "cleanClaim": spec["cleanClaim"]},
        "cleanClaim": spec["cleanClaim"], "benchmarkStatus": benchmark["status"],
        "benchmarkRequiredForCleanClaim": benchmark["requiredForCleanClaim"], "qualificationDigest": benchmark["qualificationDigest"], "required": required}
    bounds = {"executionPolicy": POLICY, "executionPolicyIdentity": {"id": "audit-native-owner-admission-v1", "version": 1, "digest": digest(encoded(POLICY))}}
    return {"schemaVersion": 1, "repositoryId": inventory["repositoryId"], "inventoryGeneration": inventory["generation"],
            "inventoryDigest": inventory["digest"], "providers": [provider], "bounds": bounds, "excludedConditionalProviders": []}


def expected_result(row, control, plan):
    source_path = row["source"]["path"]
    missing = control == "missing-manifest"
    routes = row["routes"] if control == "positive" else []
    if control == "route-cap":
        routes = [{"method": "GET", "path": "/r%d" % i, "file": source_path, "line": i + 1, "auth": "unknown"} for i in range(2000)]
    gaps = (["backend-framework-denominator-zero", "runtime-evidence-trust-unavailable"] if missing else
            ["route-evidence-gap", "route-auth-unknown", "runtime-evidence-trust-unavailable"] if routes else
            ["route-denominator-gap", "runtime-evidence-trust-unavailable"])
    read = 0 if missing else 1 if control == "drift" else 2
    if control == "drift":
        gaps.append("producer-skipped:" + source_path + ":drift")
    if control in ("unsupported", "quoted-decoy"):
        gaps.append("producer-backend-source-syntax-unsupported:" + source_path)
    if control == "route-cap":
        gaps.append("producer-backend-route-cap:express:2000")
    analysis = {"status": "unproven", "complete": False, "denominator": {"kind": "backend-framework-routes", "expected": len(routes), "examined": read},
        "findings": [], "coverageGaps": [{"kind": gap} for gap in gaps], "certificationClaim": False,
        "protocolValidation": {"scope": "caller-supplied-values-and-reference-metadata", "expected": len(routes), "examined": 0}}
    details = {"nativeInput": {} if missing else {"artifacts": {"backendFrameworks": [{"name": row["framework"], "routes": routes}]},
            "producer": {"kind": "self-sourced", "filesRead": read}}, "nativeAnalysis": analysis, "findingEvidence": {}, "findingLocations": {}}
    result_gaps = list(gaps)
    if missing:
        result_gaps.append("unavailable:no-backend-framework-detected")
        details["availability"] = {"state": "unavailable", "reason": "no-backend-framework-detected"}
    provider = plan["providers"][0]
    return {"schema_version": 1, "provider": ID, "applicable": True, "required": provider["required"], "status": "partial", "complete": False,
        "coverage": {"denominator_digest": provider["configuration"]["denominatorDigest"], "expected": provider["configuration"]["denominatorCount"],
            "examined": read, "gaps": result_gaps}, "findings": [], "coverage_gaps": result_gaps, "degradation": gaps, "details": details}


def replay_stream(raw, corpus, spec, benchmark, retained, live=False):
    require(type(raw) is bytes and raw.endswith(b"\n") and b"\r" not in raw and len(raw) <= 16 * 1024 * 1024, "raw native stream framing/bound differs")
    lines = raw.splitlines()
    require(len(lines) == len(CONTROLS) and all(lines), "native stream truncated/duplicated/extra control")
    observations = [parsed(line) for line in lines]
    for case_id, line, observation in zip(CONTROLS, lines, observations):
        keys(observation, OBSERVATION_KEYS)
        require(line == encoded(observation), "raw native line was rewritten/noncanonical")
        row, control, files, after = fixed_case(corpus, case_id)
        fixture = str(PurePosixPath(retained) / "fixtures" / case_id)
        same({key: observation[key] for key in ("caseId", "framework", "control", "fixtureRoot", "fixtureFiles", "postFreezeFiles")},
             {"caseId": case_id, "framework": row["framework"], "control": control, "fixtureRoot": fixture,
              "fixtureFiles": files, "postFreezeFiles": after}, "native fixture/control bytes differ")
        inventory = expected_inventory(case_id, row, files)
        same(observation["inventory"], inventory, "filesystem inventory/denominator altered")
        plan = expected_plan(spec, inventory, benchmark)
        same(observation["frozenPlan"], plan, "frozen original provider/selector/bounds altered")
        pd = digest(encoded(plan))
        require(observation["planDigest"] == pd and observation["planSignature"] == "hmac-sha256:" + hmac.new(KEY, encoded(plan), hashlib.sha256).hexdigest(), "native frozen plan signature differs")
        same(observation["dispatch"], {"planDigest": pd, "inventoryDigest": inventory["digest"], "plannedProviders": [ID], "pendingHost": [], "skipped": False}, "original native dispatch absent")
        same(observation["nativeResult"], expected_result(row, control, plan), "full native source result differs; unavailable is never clean")
        if live:
            directory = Path(fixture)
            require(directory.is_dir() and not directory.is_symlink(), "retained native source missing")
            actual = []
            for path in directory.rglob("*"):
                require(not path.is_symlink(), "retained source symlink")
                if path.is_file():
                    actual.append(path.relative_to(directory).as_posix())
            same(sorted(actual), sorted(after), "retained fixture file set differs")
            for path, body in after.items():
                require(source(directory, path).read_bytes() == body.encode(), "retained source bytes differ")
    return observations


def execution_benchmark(benchmark):
    """Bounded historical semantics only; canonical enrollment must authenticate provenance."""
    require(type(benchmark) is dict, "execution benchmark must be an object")
    require(benchmark.get("status") in ("unproven", "qualified"), "execution benchmark status differs")
    require(benchmark.get("requiredForCleanClaim") is False, "execution benchmark clean claim widened")
    if benchmark["status"] == "unproven":
        wanted = {"status": "unproven", "requiredForCleanClaim": False, "qualificationDigest": None}
        if "qualification" in benchmark:
            wanted["qualification"] = None
        same(benchmark, wanted, "unproven execution benchmark differs")
        return
    keys(benchmark, {"status", "requiredForCleanClaim", "qualificationDigest", "qualification"})
    qualification = benchmark["qualification"]
    keys(qualification, {"basis", "index", "record", "recordSha256", "originalQualificationDigest", "validationBasis",
        "stage", "scope", "fixtureScope", "coverageScope", "runtimeExamined", *FALSE_CLAIMS})
    for field in ("recordSha256", "originalQualificationDigest"):
        require(type(qualification[field]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", qualification[field]),
                "historical qualification digest malformed")
    original = qualification["originalQualificationDigest"].removeprefix("sha256:")
    same({field: qualification[field] for field in ("basis", "index", "record", "validationBasis", "stage", "scope", "fixtureScope", "coverageScope")},
        {"basis": "retained-provider-accuracy", "index": "qualification/provider-accuracy/index.json",
         "record": "qualification/provider-accuracy/records/" + ID + "/" + original + ".json",
         "validationBasis": "native-family-validator", "stage": "fact-output", "scope": SCOPE, "fixtureScope": SCOPE,
         "coverageScope": "exact thirteen named literal source facts only; runtime, mount composition & auth remain unproven"},
        "historical qualification scope/reference widened")
    require(type(qualification["runtimeExamined"]) is int and qualification["runtimeExamined"] == 0,
            "historical qualification runtime claim widened")
    for field in FALSE_CLAIMS:
        require(qualification[field] is False, "historical qualification claim widened: " + field)
    require(benchmark["qualificationDigest"] == digest(encoded(qualification)), "historical qualification seal differs")


def validate_record(root, record, raw, live=False):
    root = Path(root).resolve()
    keys(record, RECORD_KEYS)
    same({key: record[key] for key in ("schema", "provider", "family", "stage", "scope", "executionPath", "status", "coverageState", "qualificationEligible", "modelCalls", "runtimeExamined")},
        {"schema": SCHEMA, "provider": ID, "family": FAMILY, "stage": "fact-output", "scope": SCOPE,
         "executionPath": "native-frozen-plan-self-sourced-backend-source-facts", "status": "pass", "coverageState": "scoped-controls-complete",
         "qualificationEligible": True, "modelCalls": 0, "runtimeExamined": 0}, "dedicated bounded source identity/eligibility differs")
    for key in FALSE_CLAIMS:
        require(record[key] is False, "unsupported qualification claim: " + key)
    require(record["qualificationDigest"] == digest(encoded({k: v for k, v in record.items() if k != "qualificationDigest"})), "source record seal differs")
    same(record["frameworkDenominator"], FRAMEWORKS, "thirteen-framework denominator narrowed")
    same(record["controls"], CONTROLS, "native controls missing/duplicated/reordered")
    corpus = contract(root)
    registry = parsed(source(root, "src/registry/providers.json").read_bytes())
    specs = [row for row in registry["providers"] if row["id"] == ID]
    require(len(specs) == 1, "original provider missing/duplicated")
    spec = {key: value for key, value in specs[0].items() if key != "benchmark"}
    keys(record["binding"], {"providerSpec", "providerSpecDigest", "benchmarkAtExecution", "fixture", "sources", "sourcesDigest"})
    benchmark = record["binding"]["benchmarkAtExecution"]
    execution_benchmark(benchmark)
    if live:
        same(benchmark, specs[0]["benchmark"], "live execution benchmark differs from shipped registry")
    # Retained replay binds every frozen plan to this complete historical object.
    # audit-qualification-records must then authenticate original record/stream/summary provenance.
    sources = {path: digest(source(root, path).read_bytes()) for path in source_files(root)}
    same(record["binding"], {"providerSpec": spec, "providerSpecDigest": digest(encoded(spec)), "benchmarkAtExecution": benchmark,
        "fixture": HARNESS, "sources": sources, "sourcesDigest": digest(encoded(sources))}, "full production source closure/provider contract stale")
    require(record["providerVersion"] == spec["providerVersion"], "provider version differs")
    retained = record["retainedRoot"]
    path = PurePosixPath(retained)
    require(type(retained) is str and path.is_absolute() and str(path) == retained and ".." not in path.parts and "\\" not in retained
            and path.name == "backend-source" and path.parent.name == "legion-provider-qualification", "dedicated retained root differs")
    same(record["rawStream"], {"path": "native-results.jsonl", "sha256": digest(raw), "bytes": len(raw), "cases": len(CONTROLS)}, "native raw stream binding differs")
    replay_stream(raw, corpus, spec, record["binding"]["benchmarkAtExecution"], retained, live)
    same(record["metrics"], {"frameworks": 13, "cases": 60, "matched": 60, "mismatched": 0, "runtimeExamined": 0}, "exact named control metrics differ")
    return {"provider": ID, "stage": "fact-output", "scope": SCOPE, "qualificationDigest": record["qualificationDigest"],
        "qualificationEligible": True, "frameworks": 13, "cases": 60, "runtimeExamined": 0, **{key: False for key in FALSE_CLAIMS}}


def rejection_controls(root, record, raw):
    """Resealed semantic mutations must fail; checksum rejection alone is insufficient."""
    originals = [parsed(line) for line in raw.splitlines()]
    def reject(change_record=None, change_rows=None, replacement=None):
        changed, rows = copy.deepcopy(record), copy.deepcopy(originals)
        if change_rows:
            change_rows(rows)
        body = replacement if replacement is not None else b"".join(encoded(row) + b"\n" for row in rows)
        changed["rawStream"].update(sha256=digest(body), bytes=len(body))
        if change_record:
            change_record(changed)
        changed.pop("qualificationDigest", None)
        changed["qualificationDigest"] = digest(encoded(changed))
        try:
            validate_record(root, changed, body)
        except (AssertionError, KeyError, ValueError, TypeError, StopIteration):
            return
        raise AssertionError("native source mutation incorrectly accepted")
    reject(change_record=lambda r: r.update(runtimeQualified=True))
    reject(change_record=lambda r: r.update(authQualified=True))
    reject(change_record=lambda r: r.update(productionQualification=True))
    reject(change_record=lambda r: r.update(frameworkDenominator=FRAMEWORKS[:-1]))
    reject(change_record=lambda r: r.update(modelCalls=False))
    reject(change_record=lambda r: r["binding"]["sources"].pop(HARNESS))
    reject(change_rows=lambda rows: rows.pop())
    reject(change_rows=lambda rows: rows.__setitem__(1, rows[0]))
    reject(change_rows=lambda rows: rows[0]["fixtureFiles"].update({"src/server.js": "surrogate\n"}))
    reject(change_rows=lambda rows: rows[0]["frozenPlan"]["providers"][0]["configuration"].update(input={"complete": True}))
    reject(change_rows=lambda rows: rows[0]["nativeResult"].update(complete=True))
    reject(change_rows=lambda rows: rows[0]["nativeResult"]["details"]["nativeInput"]["artifacts"]["backendFrameworks"][0]["routes"][0].update(auth="authenticated"))
    reject(change_rows=lambda rows: rows[0]["nativeResult"]["details"]["nativeInput"]["artifacts"]["backendFrameworks"][0]["routes"][0].update(path="/tampered"))
    reject(change_rows=lambda rows: rows[0]["nativeResult"]["coverage_gaps"].clear())
    reject(change_rows=lambda rows: rows[2]["nativeResult"]["details"].pop("availability"))
    reject(change_rows=lambda rows: rows[3]["nativeResult"]["coverage_gaps"].remove("producer-skipped:src/server.js:drift"))
    reject(change_rows=lambda rows: rows[-3]["nativeResult"]["details"]["nativeInput"]["artifacts"]["backendFrameworks"][0].update(routes=[{"path": "/decoy"}]))
    reject(replacement=raw + raw.splitlines()[0] + b"\n")
    reject(replacement=raw[:-1])
    reject(replacement=raw.replace(b'"caseId":', b'"caseId":"duplicate","caseId":', 1))
    return 20


def validate(root, receipts):
    receipts = Path(receipts)
    require(receipts.is_absolute() and not receipts.is_symlink(), "native receipt root unsafe")
    record = parsed(source(receipts, "framework_backend.json").read_bytes())
    require(record["retainedRoot"] == str(receipts), "receipt root was rewritten")
    raw = source(receipts, "native-results.jsonl").read_bytes()
    result = validate_record(root, record, raw, live=True)
    require(rejection_controls(root, record, raw) == 20, "semantic mutations incomplete")
    return {"records": [result], "modelCalls": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    print("BACKEND_SOURCE_FACTS_ACCURACY_SUMMARY " + json.dumps(validate(args.root, args.receipts), sort_keys=True))
