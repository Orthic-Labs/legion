#!/usr/bin/env python3
"""Validate measured native output records against this exact checkout.

This gate does not promote registry statuses. Partial records retain missing
tool/host coverage, even when observed native output has no FP/FN.
"""

import argparse
import hashlib
import json
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def bound_file(root, path):
    assert not path.is_symlink(), f"symlink source binding: {path}"
    return {"path": path.relative_to(root).as_posix(), "digest": digest(path.read_bytes())}


def validate(root, directory, expected):
    registry = json.loads((root / "src/registry/providers.json").read_bytes())
    specs = {row["id"]: row for row in registry["providers"]}
    files = sorted(directory.glob("*.json"))
    assert len(files) == len(expected), ("receipt count", len(files), len(expected))
    found = {}
    for path in files:
        record = json.loads(path.read_bytes())
        provider = record["provider"]
        assert provider in expected and provider not in found, ("unexpected/duplicate provider", provider)
        plan = expected[provider]
        measurement_kind = plan["measurementKind"]
        assert record["schema"] == "legion-file-provider-accuracy/1"
        assert record["stage"] == plan["stage"], provider
        assert record["executionPath"] == "native-sdk-frozen-plan-file-only"
        assert record["modelCalls"] == 0
        assert record["status"] == "pass", (provider, record["metrics"])
        assert record["measurementStatus"] == record["status"]
        assert record["measurementKind"] == measurement_kind, provider
        assert bool(record["coverageGaps"]) == (record["coverageState"] == "partial")
        assert record["coverageState"] in ("complete", "partial")
        assert record["qualificationEligible"] == (record["coverageState"] == "complete")
        assert record["qualificationEligible"] == plan["qualificationEligible"], provider
        if measurement_kind == "fact-output":
            assert record["stage"] == "fact-output", provider
            assert record["coverageState"] == "complete" and record["coverageGaps"] == [], provider
            assert record["requiredDependencies"] == {
                "productionDispatch": "exercised",
                "positiveControl": "exercised",
                "absenceControl": "exercised",
                "scope": "named native facts; exact full object equality",
                "externalExecution": "not-required",
            }, provider
        elif measurement_kind == "verification-outcome":
            assert record["stage"] == "outcome", provider
            assert record["coverageState"] == "complete" and record["coverageGaps"] == [], provider
            assert record["requiredDependencies"] == {
                "productionDispatch": "exercised",
                "acceptanceControl": "exercised",
                "rejectionControl": "exercised",
                "scope": "named verifier cases; no claim about untested outcomes",
                "externalExecution": "not-required",
            }, provider
        else:
            assert record["requiredDependencies"] == {
                "productionDispatch": "exercised", "positiveControl": "exercised",
                "negativeControl": "exercised", "scope": "named corpus; no claim about untested rules",
                "externalExecution": "not-required" if record["coverageState"] == "complete" else "missing",
            }, provider
        binding = record["binding"]
        roots = ["engine/crates/legion-audit/src", "engine/crates/legion-provider-sdk/src",
                 "engine/crates/legion-contracts/src", "engine/crates/legion-rules/src",
                 "engine/crates/legion-effects/src",
                 "src/registry/rules", "src/registry/controls"]
        assert binding["implementationRoots"] == roots, provider
        implementation = []
        for tree in roots:
            for file in (root / tree).rglob("*"):
                assert not file.is_symlink(), file
                if file.is_file():
                    implementation.append(bound_file(root, file))
        for file in ("engine/Cargo.lock", "engine/Cargo.toml", "engine/crates/legion-audit/Cargo.toml",
                     "engine/crates/legion-provider-sdk/Cargo.toml", "engine/crates/legion-contracts/Cargo.toml",
                     "engine/crates/legion-rules/Cargo.toml", "engine/crates/legion-effects/Cargo.toml",
                     "engine/crates/legion-audit/tests/support/accuracy_receipt.rs"):
            implementation.append(bound_file(root, root / file))
        implementation.sort(key=lambda row: row["path"])
        assert binding["implementationFileCount"] == len(implementation), provider
        assert binding["implementationDigest"] == digest(canonical(implementation)), provider
        spec = dict(specs[provider])
        spec.pop("benchmark", None)
        assert record["providerVersion"] == spec["providerVersion"], provider
        assert binding["providerSpecDigest"] == digest(canonical(spec)), provider
        fixtures = binding["fixtures"]
        assert [row["path"] for row in fixtures] == expected[provider]["fixtures"], provider
        for fixture in fixtures:
            assert fixture == bound_file(root, root / fixture["path"]), (provider, fixture)
        if measurement_kind == "fact-output":
            cases = record["factCases"]
            ids = [row["caseId"] for row in cases]
            assert len(ids) == len(set(ids)), provider
            controls = set()
            matched = 0
            expected_facts = {}
            for case in cases:
                control = case["controlKind"]
                assert control in ("positive", "absence"), (provider, control)
                controls.add(control)
                wanted, actual = case["expected"], case["actual"]
                same = canonical(wanted) == canonical(actual)
                assert case["matched"] is same, provider
                matched += same
                expected_facts.setdefault(control, wanted)
            assert {"positive", "absence"} <= controls, (provider, "missing positive/absence fact control")
            assert canonical(expected_facts["positive"]) != canonical(expected_facts["absence"]), (
                provider, "positive/absence controls do not contrast"
            )
            assert matched == len(cases), (provider, "fact-output mismatch")
            assert record["metrics"] == {
                "cases": len(cases), "matched": matched, "mismatched": len(cases) - matched
            }, provider
        elif measurement_kind == "verification-outcome":
            cases = record["outcomeCases"]
            ids = [row["caseId"] for row in cases]
            assert len(ids) == len(set(ids)), provider
            matched = accepted = rejected = 0
            for case in cases:
                assert case["expected"] in ("accepted", "unproven", "rejected"), provider
                assert case["actual"] in ("accepted", "unproven", "rejected"), provider
                for key in ("expectedGaps", "actualGaps"):
                    gaps = case[key]
                    assert gaps == sorted(gaps) and len(gaps) == len(set(gaps)), (provider, key)
                same = case["expected"] == case["actual"] and case["expectedGaps"] == case["actualGaps"]
                assert case["matched"] is same, provider
                matched += same
                accepted += case["expected"] == "accepted"
                rejected += case["expected"] in ("unproven", "rejected")
            assert accepted > 0 and rejected > 0, (provider, "missing acceptance/rejection control")
            assert matched == len(cases), (provider, "outcome mismatch")
            assert record["metrics"] == {
                "cases": len(cases), "matched": matched, "mismatched": len(cases) - matched
            }, provider
        else:
            cases = record["cases"]
            ids = [row["caseId"] for row in cases]
            assert len(ids) == len(set(ids)), provider
            tp = fp = fn = positive = clean = 0
            for case in cases:
                wanted, actual = case["expected"], case["actual"]
                assert len(wanted) == len(set(wanted)), provider
                w, a = set(wanted), set(actual)
                counts = (len(w & a), len(a - w) + len(actual) - len(a), len(w - a))
                assert counts == (case["truePositives"], case["falsePositives"], case["falseNegatives"])
                tp += counts[0]
                fp += counts[1]
                fn += counts[2]
                positive += bool(w)
                clean += not w
            assert positive > 0 and clean > 0, (provider, "missing positive/clean control")
            assert (fp, fn) == (0, 0), (provider, fp, fn)
            assert record["metrics"] == {
                "truePositives": tp, "falsePositives": fp, "falseNegatives": fn,
                "precision": tp / (tp + fp), "recall": tp / (tp + fn),
                "positiveCases": positive, "cleanCases": clean,
            }, provider
        claimed_digest = record.pop("qualificationDigest")
        assert claimed_digest == digest(canonical(record)), provider
        found[provider] = {"stage": record["stage"], "measurementKind": record["measurementKind"],
                           "coverageState": record["coverageState"],
                           "qualificationEligible": record["qualificationEligible"],
                           "qualificationDigest": claimed_digest, "metrics": record["metrics"],
                           "coverageGaps": record["coverageGaps"]}
    assert set(found) == set(expected), ("missing providers", set(expected) - set(found))
    return found


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = json.loads((root / "bench/provider-accuracy-plan.json").read_bytes())
    expected = {row["provider"]: row for row in manifest["providers"]}
    assert len(expected) == len(manifest["providers"]), "duplicate manifest provider"
    result = validate(root, args.receipts, expected)
    print("FILE_PROVIDER_ACCURACY_SUMMARY " + json.dumps(result, sort_keys=True, separators=(",", ":")))
