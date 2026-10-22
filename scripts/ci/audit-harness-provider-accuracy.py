#!/usr/bin/env python3
"""Validate original bench, quality & IaC receipts; never promotes records."""

import argparse
import json
from pathlib import Path
import runpy


def validate(root, receipts, group):
    api = runpy.run_path(str(Path(__file__).with_name("audit-qualification-records.py")))
    root, receipts = Path(root).resolve(), Path(receipts)
    api["require"](group in api["PAIRED_HARNESS_GROUPS"], "unsupported paired harness group")
    api["require"](receipts.is_absolute() and receipts.is_dir() and not receipts.is_symlink(),
                   "original receipt directory missing/noncanonical")
    for parent in receipts.parents:
        api["require"](not parent.is_symlink(), "symlink in original receipt directory")
    registry = api["load"](api["relative_file"](root, "src/registry/providers.json"))["providers"]
    api["require"](len({spec["id"] for spec in registry}) == len(registry), "duplicate registry provider")
    specs = {spec["id"]: spec for spec in registry}
    results = []
    for provider in api["PAIRED_HARNESS_GROUPS"][group]:
        filename = "bench_recall_receipt.json" if group == "bench" else provider.replace(".", "_") + ".json"
        path = api["relative_file"](receipts, filename)
        raw = path.read_bytes()
        row = api["parsed"](raw, path)
        entry = api["paired_harness_entry"](provider, row)
        results.append(api["validate_paired_harness_record"](root, entry, row, specs, raw))
    return {"records": results, "modelCalls": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--receipts", required=True, type=Path)
    parser.add_argument("--group", required=True, choices=("bench", "quality", "trivy-iac"))
    args = parser.parse_args()
    result = validate(args.root, args.receipts, args.group)
    print("HARNESS_PROVIDER_ACCURACY_SUMMARY " + json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False))


if __name__ == "__main__":
    main()
