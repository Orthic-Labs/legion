#!/usr/bin/env python3
"""Validate existing owner provisioned public pins; never install, enroll, sign or admit jobs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import tomllib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    api = runpy.run_path(str(root / "scripts/ci/audit-quality-test-accuracy.py"))
    require = api["require"]
    require(os.uname().sysname == "Darwin", "managed native macOS owner required")
    path = Path(os.environ["LEGION_ATTESTED_RUNS_ENROLLMENT"])
    require(path.is_absolute() and path.is_file() and not path.is_symlink() and not path.resolve().is_relative_to(root), "authentic enrollment must be outside checkout")
    pin = api["parsed"](path.read_bytes()); api["pin_valid"](pin)
    require(api["digest"](api["encoded"](pin)) == os.environ["LEGION_QUALITY_TEST_EXPECTED_ENROLLMENT_SHA256"], "public host enrollment differs from owner-provided CI pin")
    client = Path(pin["clientExecutable"])
    require(client.is_file() and not client.is_symlink() and client == client.resolve() and not client.is_relative_to(root), "canonical native owner client unavailable")
    require(hashlib.sha256(client.read_bytes()).hexdigest() == pin["clientDigest"], "installed owner client pin mismatch")
    logs = Path(os.environ["LEGION_QUALITY_TEST_BROKER_LOG_ROOT"])
    require(logs.is_absolute() and logs.is_dir() and not logs.is_symlink() and logs == logs.resolve() and not logs.is_relative_to(root), "canonical readable owner broker log root required")
    out = Path(os.environ["LEGION_QUALITY_TEST_EVIDENCE"])
    require(out.is_absolute() and not out.exists() and not out.is_relative_to(root) and not path.is_relative_to(out), "fresh external evidence root required")
    toolchain = tomllib.loads((root / "engine/rust-toolchain.toml").read_text())
    require(toolchain["toolchain"]["channel"] == "1.98.0", "qualification requires current source-pinned managed Rust 1.98.0")
    print(json.dumps({"schema":"legion-quality-test-native-prerequisites/1","hostEnrollmentDigest":api["digest"](api["encoded"](pin)),
                      "clientDigest":"sha256:" + pin["clientDigest"],"brokerDigest":"sha256:" + pin["brokerDigest"],
                      "host":pin["host"],"ownerAdmissionClaim":False,"status":"existing-public-pins-validated"}, sort_keys=True))


if __name__ == "__main__":
    main()
