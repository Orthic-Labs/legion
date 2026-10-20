#!/usr/bin/env python3
"""Validate dedicated native generic-source controls; CI authentication stays maintainer-owned."""
import argparse
import copy
import hashlib
import hmac
import json
from pathlib import Path, PurePosixPath
import re

ID = "code.long-tail"
HARNESS = "engine/crates/legion-audit/tests/code_long_tail_accuracy.rs"
CORPUS = "engine/crates/legion-audit/tests/fixtures/code-long-tail/controls.json"
VALIDATOR = "scripts/ci/audit-code-long-tail-accuracy.py"
FAMILY_SCOPE = "constructed frozen native generic-source controls; unsupported-language coverage remains partial"
RULES = ["debt-marker", "duplicate-block", "oversized-file"]
CONTROLS = ("debt-positive", "nonempty-clean", "oversized-1500", "oversized-1501",
            "duplicate-120-boundary", "duplicate-below-120", "duplicate-below-six", "duplicate-normalization",
            "duplicate-same-file", "selection-historical", "selection-unknown-noextension", "selection-owned-elsewhere",
            "missing", "drift", "symlink", "symlink-parent", "not-utf8", "file-byte-cap", "total-byte-cap",
            "findings-cap", "duplicate-window-cap", "skip-record-cap", "injected-no-rules", "empty-denominator")
HISTORICAL = "astro bash bat cjs cts css cxx dart erl ex exs gql graphql hrl html kts mjs mts nsh nsi ps1 psm1 rb sh sql svelte vbs vue zsh".split()
CLAIMED = "c cc cpp cxx h hpp cs fs vb go js jsx ts tsx cjs mjs cts mts java kt kts scala swift m mm php rb py rs".split()
UNSAFE_PATHS = ["../outside.sh", "/outside.sh", "directory/../outside.sh", "./outside.sh", ""]
SOURCE_ROOTS = ["engine/crates/" + name + "/src" for name in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")] + ["src/registry/rules", "src/registry/controls"]
SOURCE_FILES = ["engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml", HARNESS, CORPUS, VALIDATOR] + ["engine/crates/" + name + "/Cargo.toml" for name in ("legion-audit", "legion-effects", "legion-provider-sdk", "legion-contracts", "legion-rules")]


def require(value, message):
    if not value:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def source(root, relative):
    path = PurePosixPath(relative)
    require(relative and not path.is_absolute() and str(path) == relative and ".." not in path.parts and "\\" not in relative, "unsafe source path")
    actual = root
    for part in path.parts:
        actual /= part
        require(not actual.is_symlink(), "source symlink refused")
    require(actual.is_file(), "source missing: " + relative)
    return actual


def source_files(root):
    files = set(SOURCE_FILES)
    for name in SOURCE_ROOTS:
        directory = root / name
        require(directory.is_dir() and not directory.is_symlink(), "source root missing/unsafe")
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "source closure symlink")
            relative = path.relative_to(root).as_posix()
            generated = re.fullmatch(r"engine/crates/legion-audit/src/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", relative)
            if path.is_file() and not generated:
                files.add(relative)
    return sorted(files)


def fixture_bytes(file):
    if "rawBytes" in file:
        return bytes(file["rawBytes"])
    if "text" in file:
        return file["text"].encode()
    recipe = file["recipe"]
    if recipe["kind"] == "blank-lines":
        return b"\n" * recipe["lines"]
    require(recipe["kind"] == "digits", "unknown fixed source recipe")
    lines = [("  \t" if recipe["indent"] else "") + str(n).zfill(recipe["width"]) + ("  " if recipe["indent"] else "") + "\n" for n in range(recipe["lines"])]
    return ("".join(lines) * recipe["repeats"]).encode()


def extension(path):
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[1].lower() if "." in name else ""


def unsupported(paths):
    grouped = {}
    for path in paths:
        grouped.setdefault(extension(path) or "(no extension)", []).append(path)
    return [{"kind": "missing-language-provider", "language": ext, "extension": ext,
             "pathCount": len(grouped[ext]), "samplePaths": grouped[ext][:20]} for ext in sorted(grouped)]


def effective_limits(case):
    out = {"maxFileBytes": 1048576, "maxTotalBytes": 67108864, "maxFindings": 500,
           "maxDuplicateWindows": 500000, "maxSkipRecords": 1000}
    require(set(case["limits"]) <= set(out), "unknown control limit")
    out.update(case["limits"])
    return out


def validate_native_producer(actual, selected, successful, accounting, files, limits):
    # The generic provider has no required contexts; native production emits an empty object.
    producer = {"mode": "self-sourced", "filesExpected": len(selected), "filesRead": len(successful),
                "sourceFilesExpected": len(selected), "sourceFilesRead": len(successful), "contextFilesExpected": 0,
                "contextFilesRead": 0, "contextBytesRead": 0, "contextAccounting": None, "context": {},
                "bytesRead": sum(len(files[path]) for path in successful), "rules": RULES, "sourceAccounting": accounting,
                "limits": {key: limits[key] for key in ("maxFileBytes", "maxTotalBytes", "maxFindings")},
                "toolDiscovery": [], "toolReceipts": [], "deferredCommands": []}
    same(actual, producer, "native source accounting/rules/bounds differ")


def verify_live(root, case, files):
    require(root.is_absolute() and not root.is_symlink() and root.is_dir(), "retained fixture root missing/unsafe")
    mode = case["mutation"]
    for path, raw in files.items():
        actual = root / path
        if mode == "delete":
            require(not actual.exists() and not actual.is_symlink(), "missing-file control restored")
        elif mode == "drift":
            require(not actual.is_symlink() and actual.read_bytes() == b"# TODO replacement\n", "source-drift mutation differs")
        elif mode == "symlink":
            require(actual.is_symlink() and str(actual.readlink()) == "target.txt", "direct symlink mutation absent")
            require(not (root / "target.txt").is_symlink() and (root / "target.txt").read_bytes() == b"# TODO symlink target\n", "symlink target fixture differs")
        elif mode == "symlink-parent":
            require((root / "directory").is_symlink() and str((root / "directory").readlink()) == "target-directory", "ancestor symlink mutation absent")
            require(source(root, "target-directory/worker.sh").read_bytes() == raw, "ancestor symlink original fixture differs")
        else:
            require(source(root, path).read_bytes() == raw, "retained fixture bytes differ")


def validate_record(repository_root, record, live=False):
    root = Path(repository_root).resolve()
    require(type(live) is bool and record["schema"] == "legion-code-long-tail-native-accuracy/1" and record["provider"] == ID
            and record["family"] == "code-long-tail" and record["stage"] == "finding" and record["scope"] == FAMILY_SCOPE
            and record["executionPath"] == "native-frozen-plan-self-sourced-generic-source", "dedicated long-tail identity/scope differs")
    for flag in ("productionQualification", "wholeProviderQualified", "auditCleanClaim", "compilerCoverageQualified", "languageCoverageQualified"):
        require(record[flag] is False, "generic inspection expanded coverage claim: " + flag)
    require(record["qualificationEligible"] is True and record["status"] == "pass"
            and record["coverageState"] == "scoped-controls-complete" and type(record["modelCalls"]) is int and record["modelCalls"] == 0, "dedicated controls incomplete")
    require(record["qualificationDigest"] == digest(encoded({k: v for k, v in record.items() if k != "qualificationDigest"})), "qualification seal differs")
    registry = parsed(source(root, "src/registry/providers.json").read_bytes())
    specs = [item for item in registry["providers"] if item["id"] == ID]
    require(len(specs) == 1, "provider missing/duplicated")
    spec = {k: v for k, v in specs[0].items() if k != "benchmark"}
    binding = record["binding"]
    same(binding["providerSpec"], spec, "original provider contract differs")
    require(record["providerVersion"] == spec["providerVersion"] and binding["providerSpecDigest"] == digest(encoded(spec))
            and binding["fixture"] == HARNESS, "provider/harness binding differs")
    sources = {path: digest(source(root, path).read_bytes()) for path in source_files(root)}
    same(binding["sources"], sources, "source closure stale/incomplete")
    require(binding["sourcesDigest"] == digest(encoded(sources)), "source closure seal differs")
    contract = parsed(source(root, CORPUS).read_bytes())
    same(contract["historicalExtensions"], HISTORICAL, "historical selection control set differs")
    same(contract["claimedExtensions"], CLAIMED, "owned-language exclusion control set differs")
    same(contract["unsafePaths"], UNSAFE_PATHS, "unsafe path controls differ")
    same(contract["thresholds"], {"oversizedLines": 1500, "duplicateWindow": 6, "duplicateMinChars": 120}, "rule boundaries differ")
    same(record["requiredContract"], {"tools": [], "contexts": [], "rules": RULES, "unsupportedLanguageGapsMandatory": True, "thresholds": contract["thresholds"]}, "original generic-source contract changed")
    require([case["caseId"] for case in contract["cases"]] == list(CONTROLS)
            and [case["caseId"] for case in record["cases"]] == list(CONTROLS), "missing/duplicated native control")
    retained = None
    for case, expected in zip(record["cases"], contract["cases"]):
        mode = expected["caseId"]
        require(case["controlMatched"] is True and case["inventoryOrigin"] == "constructed-digest-bound-files-v1", "control/inventory origin differs")
        files = {file["path"]: fixture_bytes(file) for file in expected["files"]}
        fixtures = {path: {"digest": digest(raw), "bytes": len(raw)} for path, raw in files.items()}
        same(case["fixtureSources"], fixtures, "literal fixture hashes differ")
        fixture_root = PurePosixPath(case["fixtureRoot"])
        require(fixture_root.is_absolute() and str(fixture_root) == case["fixtureRoot"] and ".." not in fixture_root.parts
                and fixture_root.name == mode and fixture_root.parent.name == "fixtures"
                and fixture_root.parent.parent.name == "code-long-tail"
                and fixture_root.parent.parent.parent.name == "legion-provider-qualification", "retained native fixture path differs")
        retained = retained or fixture_root.parent.parent
        require(retained == fixture_root.parent.parent, "mixed native fixture roots")
        if live:
            verify_live(Path(str(fixture_root)), expected, files)
        inventory, plan = case["inventory"], case["frozenPlan"]
        entries = [{"path": file["path"], "symbols": [], "dependencies": [], "packageScripts": [],
                    "sourceFile": file["sourceFile"], "digest": fixtures[file["path"]]["digest"]} for file in expected["files"]]
        entries.sort(key=lambda item: item["path"])
        identity = [1, mode, "constructed-digest-bound-files-v1", entries]
        same(inventory, {"schemaVersion": 1, "repositoryId": mode, "generation": identity[2], "entries": entries,
                         "digest": digest(encoded(identity))}, "frozen source denominator differs")
        require(plan["inventoryDigest"] == inventory["digest"] and plan["repositoryId"] == mode
                and plan["inventoryGeneration"] == inventory["generation"] and case["planDigest"] == digest(encoded(plan))
                and case["planSignature"] == "hmac-sha256:" + hmac.new(b"code-long-tail-constructed-fixture-key", encoded(plan), hashlib.sha256).hexdigest(), "frozen plan seal differs")
        require(len(plan["providers"]) == 1 and plan["providers"][0]["id"] == ID
                and plan["providers"][0]["version"] == spec["providerVersion"], "frozen original provider differs")
        configuration = plan["providers"][0]["configuration"]
        same(configuration["selector"], spec["selector"], "original selector replaced")
        same(spec["selector"], {"op": "always"}, "original always selector differs")
        same(configuration["runner"], spec["runner"], "original native route replaced")
        require("input" not in configuration, "frozen provider surrogate input")
        denominator = inventory["digest"]
        require(configuration["denominatorCount"] == len(entries) and configuration["denominatorDigest"] == denominator, "frozen denominator seal differs")
        result, selected = case["nativeResult"], expected["selected"]
        require(result["provider"] == ID and result["complete"] is False and result["degradation"] == [], "native generic-source result claimed complete/other contract")
        wanted_findings, evidence, locations = [], {}, {}
        for finding in expected["expectedFindings"]:
            fid = digest((ID + "\0" + finding["ruleId"] + "\0" + finding["path"] + "\0" + str(finding["line"])).encode())
            wanted_findings.append({"id": fid, "severity": "low"})
            evidence[fid] = dict(finding, provider=ID)
            locations[fid] = [finding["path"] + ":" + str(finding["line"])]
        same(result["findings"], wanted_findings, "exact native finding output differs")
        if mode == "selection-owned-elsewhere":
            require(result["applicable"] is False and result["coverage"] is None and result["coverage_gaps"] == []
                    and result["details"]["notApplicableReason"] == "no-long-tail-files-in-inventory", "owned-language exclusion became inspected clean")
            require("nativeProducer" not in result["details"], "excluded files were inspected")
            continue
        require(result["applicable"] is True and result["status"] == "partial", "long-tail result lost partial state")
        unsupported_gaps = unsupported(selected)
        gaps = [ID + ":missing-language-provider:" + gap["language"] for gap in unsupported_gaps]
        skip_items = sorted(expected["expectedSkips"].items())[:effective_limits(expected)["maxSkipRecords"]]
        gaps += [ID + ":file-skipped:" + reason + ":" + path for path, reason in skip_items]
        gaps = sorted(set(gaps + expected["extraGaps"]))
        same(result["coverage_gaps"], gaps, "mandatory/limitation gaps omitted or invented")
        successful = [path for path in selected if path not in expected["expectedSkips"]]
        examined = len(entries) if expected["injected"] else len(successful)
        same(result["coverage"], {"denominator_digest": inventory["digest"] if expected["injected"] else denominator,
                                 "expected": len(entries), "examined": examined, "gaps": gaps}, "native frozen coverage differs")
        details = result["details"]
        if expected["injected"]:
            require("nativeProducer" not in details and "findingEvidence" not in details and "findingLocations" not in details
                    and gaps == [ID + ":no-rules-applicable"], "injected input became native inspection")
            continue
        same(details["findingEvidence"], evidence, "exact evidence/locations detached from findings")
        same(details["findingLocations"], locations, "exact evidence/locations detached from findings")
        accounting = []
        for path in selected:
            item = {"path": path, "extension": extension(path)}
            if path in expected["expectedSkips"]:
                item.update(status="skipped", reason=expected["expectedSkips"][path])
            else:
                item.update(status="examined", bytes=len(files[path]), digest=digest(files[path]), analysis="generic-source")
            accounting.append(item)
        byte_count = sum(len(files[path]) for path in successful)
        limits = effective_limits(expected)
        validate_native_producer(details["nativeProducer"], selected, successful, accounting, files, limits)
        analysis_gaps = [{"kind": "denominator-gap", "language": "generic"}] if not selected else unsupported_gaps
        analysis = {"schemaVersion": 1, "provider": "code.generic", "denominator": {"kind": "generic-files",
                    "expected": len(selected), "examined": len(successful), "variants": {"generic": len(selected)}},
                    "toolEvidence": [], "boundaries": {"generated": [], "vendor": [], "components": [], "platforms": []},
                    "facts": [{"kind": "native-metrics", "filesRead": len(successful),
                               "linesRead": sum(len(files[path].decode().splitlines()) for path in successful),
                               "bytesRead": byte_count, "rules": RULES}], "coverageGaps": analysis_gaps, "complete": False}
        same(details["nativeAnalysis"], analysis, "exact generic analysis or mandatory unsupported gaps differ")
    require([item["path"] for item in record["unsafeControls"]] == UNSAFE_PATHS, "unsafe controls missing/duplicated")
    for item in record["unsafeControls"]:
        path = item["path"]
        require(item["inventoryRejected"] is True and item["route"] == "native-producer-defense-in-depth"
                and item["expected"] == 1 and item["examined"] == 0 and item["skips"] == ["unsafe-path:" + path], "unsafe inventory/path was read or accepted")
        same(item["sourceAccounting"], [{"path": path, "extension": extension(path), "status": "skipped", "reason": "unsafe-path"}], "unsafe source accounting differs")
        require(item["analysis"]["complete"] is False and item["analysis"]["denominator"]["expected"] == 1, "unsafe source became complete")
        same(item["analysis"]["coverageGaps"], unsupported([path]), "unsafe path lost mandatory unsupported gap")
    same(record["metrics"], {"cases": len(CONTROLS), "matched": len(CONTROLS), "mismatched": 0, "unsafeControls": len(UNSAFE_PATHS)}, "control metrics differ")
    return {"provider": ID, "stage": "finding", "qualificationDigest": record["qualificationDigest"], "scope": FAMILY_SCOPE,
            "productionQualification": False, "wholeProviderQualified": False, "cases": len(CONTROLS), "matched": len(CONTROLS),
            "mismatched": 0, "unsafeControls": len(UNSAFE_PATHS), "validatorRejectionControls": 12}


def rejection_controls(root, row):
    """Tamper controls are validator evidence only, never native provider evidence."""
    mutations = [lambda r: r.update(productionQualification=True), lambda r: r.update(wholeProviderQualified=True),
                 lambda r: r.update(auditCleanClaim=True), lambda r: r.update(compilerCoverageQualified=True),
                 lambda r: r["cases"].pop(), lambda r: r["unsafeControls"].pop(),
                 lambda r: r["cases"][1]["nativeResult"].update(complete=True),
                 lambda r: r["cases"][1]["nativeResult"].update(coverage_gaps=[]),
                 lambda r: r["cases"][0]["nativeResult"]["findings"].pop(),
                 lambda r: r["cases"][0]["nativeResult"]["details"]["findingLocations"].clear(),
                 lambda r: r["cases"][0]["inventory"]["entries"][0].update(digest="sha256:" + "0" * 64),
                 lambda r: r["binding"]["sources"].pop(HARNESS)]
    for mutate in mutations:
        altered = copy.deepcopy(row)
        mutate(altered)
        altered["qualificationDigest"] = digest(encoded({k: v for k, v in altered.items() if k != "qualificationDigest"}))
        try:
            validate_record(root, altered)
        except (AssertionError, KeyError, ValueError):
            continue
        raise AssertionError("forged/incomplete long-tail control was accepted")
    return len(mutations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    require(args.receipts.name == "code-long-tail" and args.receipts.parent.name == "legion-provider-qualification", "dedicated receipt root differs")
    row = parsed(source(args.receipts, "code_long-tail.json").read_bytes())
    result = validate_record(args.root, row, live=True)
    require(rejection_controls(args.root, row) == result["validatorRejectionControls"], "validator rejection controls incomplete")
    print("CODE_LONG_TAIL_PROVIDER_ACCURACY_SUMMARY " + json.dumps({"records": [result], "modelCalls": 0}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
