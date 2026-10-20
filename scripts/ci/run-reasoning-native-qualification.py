#!/usr/bin/env python3
"""Capture one genuine production Audit run; never issue enrollment authority.

Only invoke after root authenticated CI binary retrieval & no-call proof. Raw
local execution is labelled native-host capture, never GitHub job execution.
The independent source-owned registration adapter judges retained evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load(path):
    def pairs(items):
        require(len(dict(items)) == len(items), "duplicate JSON key")
        return dict(items)
    return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "non-JSON number"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--readiness", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive-prefix", required=True)
    args = parser.parse_args()
    require(platform.system() == "Darwin", "supported native host requires macOS")
    require(os.environ.get("CLAUDECODE", "").strip()
            and os.environ.get("CLAUDE_CODE_SESSION_ID", "").strip(),
            "genuine Claude marker & current session identity are required")
    require(not any(os.environ.get(name, "").strip() for name in
                    ("CODEX_THREAD_ID", "CODEX_SESSION_ID")), "conflicting harness identity")
    require(os.environ.get("LEGION_HARNESS", "claude-code") in ("", "claude", "claude-code"),
            "declared harness differs from actual supported host")
    require(not args.binary.is_symlink() and args.binary.is_file(), "CI binary must be regular")
    binary = args.binary.resolve()
    corpus = args.corpus.resolve()
    source = corpus / "fixtures"
    require(source.is_dir() and not source.is_symlink(), "source-only fixture tree missing")
    prefix = PurePosixPath(args.archive_prefix)
    require(str(prefix) == args.archive_prefix and ".." not in prefix.parts
            and args.archive_prefix.startswith("qualification/provider-accuracy/evidence/"),
            "capture archive prefix must be canonical source-relative evidence")
    ready = load(args.readiness)
    require(ready["schema"] == "legion-reasoning-binary-retrieval-verification/1"
            and ready["method"] == "authenticated-github-artifact-retrieval"
            and ready["verified"] is True, "authenticated binary retrieval readback missing")
    identity = ready["binary"]
    require(sha(binary.read_bytes()) == identity["sha256"]
            and identity["repository"] == "Orthic-Labs/legion", "CI binary identity differs")
    require(ready["noCall"]["verified"] is True
            and ready["noCall"]["sourceCommit"] == identity["sourceCommit"]
            and ready["noCall"]["binarySha256"] == identity["sha256"],
            "exact binary has no verified no-call CI proof")
    # Fresh isolated output prevents ledger reuse, continuation or budget reset.
    require(not args.output.exists(), "capture output must be fresh")
    args.output.mkdir(parents=True)
    output = args.output.resolve()
    run = output / "native-run"
    budget = {"schema": "legion-reasoning-qualification-budget/1",
              "maxPhysicalAdmissions": 44, "perCallReservationTokens": 10000,
              "reservationCeilingTokens": 440000, "width": 1,
              "strictNoRetry": True, "installedAuditPolicyChanged": False}
    (output / "qualification-budget.json").write_text(json.dumps(budget, sort_keys=True) + "\n")
    (output / "binary-retrieval-verification.json").write_bytes(args.readiness.read_bytes())
    for name in ("cases.json", "packet-plan.json"):
        (output / name).write_bytes((corpus / name).read_bytes())

    def ref(path):
        return {"path": str(prefix / path.relative_to(output).as_posix()),
                "sha256": sha(path.read_bytes())}

    capture = {"schema": "legion-reasoning-native-host-capture/1",
               "host": {"platform": "macos", "runtime": "claude-code",
                        "sessionId": os.environ["CLAUDE_CODE_SESSION_ID"]},
               "binary": identity, "commands": [], "exports": [],
               "ledger": {"rootRun": str(run), "maxPhysicalAdmissions": 44,
                          "perCallReservationTokens": 10000, "reservationCeilingTokens": 440000,
                          "width": 1, "retries": 0, "reclaims": 0,
                          "callIds": [], "reservedTokens": 0},
               "cases": {"path": "scripts/ci/fixtures/audit-reasoning-runtime-accuracy/cases.json",
                         "sha256": sha((output / "cases.json").read_bytes())},
               "packetPlan": {"path": "scripts/ci/fixtures/audit-reasoning-runtime-accuracy/packet-plan.json",
                              "sha256": sha((output / "packet-plan.json").read_bytes())}}
    # Preserve original corpus bytes as separate archive evidence; canonical
    # capture references above bind source-owned controls, never scratch copies.
    (output / "archived-corpus.json").write_text(json.dumps({
        "cases": ref(output / "cases.json"),
        "packetPlan": ref(output / "packet-plan.json")}, sort_keys=True) + "\n")

    def save():
        (output / "capture.json").write_text(json.dumps(capture, sort_keys=True, ensure_ascii=False) + "\n")

    def command(role, argv, target_run, accepted=(0,)):
        index = len(capture["commands"])
        stdout = output / f"{index:02}-{role}.stdout.json"
        stderr = output / f"{index:02}-{role}.stderr.log"
        # Runtime owns native process lifecycle, hard call timeout & reservations.
        # No shell, model override, environment injection, retry or scanner fallback.
        with stdout.open("wb") as out, stderr.open("wb") as err:
            done = subprocess.run([str(binary), *argv], cwd=corpus,
                                  stdin=subprocess.DEVNULL, stdout=out, stderr=err, check=False)
        capture["commands"].append({"role": role, "argv": [str(binary), *argv],
                                    "cwd": str(corpus), "environmentNames": sorted(os.environ),
                                    "exitCode": done.returncode, "stdout": ref(stdout),
                                    "stderr": ref(stderr), "run": str(target_run)})
        save()
        require(done.returncode in accepted, f"native {role} failed; original streams retained")
        return load(stdout), stdout

    try:
        cases = load(corpus / "cases.json")
        command("preflight", ["audit", "check-reasoning-fixtures", "--root", str(corpus)], run)
        providers = cases["providers"] + ["security.misuse-resistance"]
        argv = ["audit", str(source), "--json", "--coverage", "exhaustive",
                "--seat-token-budget", "10000", "--run-token-budget", "440000",
                "--max-total-seats", "44", "--max-lens-seats", "1", "--out", str(run)]
        for provider in providers:
            argv.extend(["--only", provider])
        command("plan", argv, run, (0, 2))
        plan = load(run / "plan.json")
        require(Path(plan["reviewContext"]["sourceRepository"]).resolve() == source.resolve(),
                "native audited source includes material outside fixtures")
        snapshot = load(Path(plan["reviewContext"]["snapshotManifest"]))
        actual_sources = set()
        for path in source.rglob("*"):
            require(not path.is_symlink(), "fixture source refuses symlinks")
            if path.is_file():
                actual_sources.add(path.relative_to(source).as_posix())
        require(set(snapshot["files"]) == actual_sources,
                "frozen snapshot must contain exactly fixture source, excluding answer keys")
        checked, _ = command("dispatch", ["audit", "check-reasoning-dispatch", "--run", str(run)], run)
        require(checked["productionDispatchValidated"] is True and checked["modelCalls"] == 0,
                "genuine frozen dispatch no-call proof missing")
        command("run", ["audit", "run-reasoning", "--run", str(run),
                        "--strict-no-retry", "--max-calls-per-packet", "1"], run, (0, 2))
        pending = [run]
        while pending:
            current = pending.pop(0)
            verified, _ = command("verify", ["verify", str(current), "--json"], current)
            require(verified["valid"] is True and verified["runtimeCalls"]["status"] == "verified",
                    "native authentication/accounting incomplete")
            exported, path = command("export", ["audit", "export-reasoning", "--run", str(current)], current)
            capture["exports"].append(ref(path))
            capture["ledger"]["callIds"].extend(row["callId"] for row in exported["authenticatedCalls"])
            child = current / "followup"
            if child.is_dir():
                require(current == run and not child.is_symlink(), "unexpected follow-up tree")
                pending.append(child)
            save()
        capture["ledger"]["callIds"].sort()
        require(len(capture["ledger"]["callIds"]) == len(set(capture["ledger"]["callIds"])),
                "duplicate physical call across parent/follow-up")
        state = load(run / "next-state.json")
        reservations = list(state["reservations"].values())
        capture["ledger"]["reservedTokens"] = sum(row["reservedTokens"] for row in reservations)
        capture["ledger"]["retries"] = sum(bool(row["retry"]) for row in reservations)
        require(len(capture["ledger"]["callIds"]) <= 44
                and capture["ledger"]["reservedTokens"] <= 440000
                and capture["ledger"]["retries"] == 0, "cumulative qualification boundary exceeded")
        save()
    except Exception as error:
        save()
        (output / "capture-error.txt").write_text(str(error) + "\n")
        raise
    print(output / "capture.json")


if __name__ == "__main__":
    main()
