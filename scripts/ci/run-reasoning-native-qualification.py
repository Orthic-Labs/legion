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

MEMBER_PROVIDERS = (
    ("reasoning.security", "legacy.security.adjudication", "legacy.security.variant-analysis", "reasoning.correctness", "reasoning.doc-drift", "reasoning.schema"),
    ("reasoning.architecture", "reasoning.minimize", "reasoning.naming", "reasoning.dead-file", "reasoning.performance", "reasoning.ai-slop"),
    ("reasoning.a11y", "reasoning.data-safety", "reasoning.resilience", "reasoning.platform-parity", "reasoning.release-readiness"),
)
PER_CALL_TOKENS = 150000
MAX_CALLS = 44


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


def prepare_fixture_repository(original, source, output, roots):
    """Copy exact source bytes into fresh Git top-level required by Audit."""
    require(not source.exists(), "fixture source output must be fresh")
    source.mkdir()
    files = set()
    for path in sorted(original.rglob("*")):
        require(not path.is_symlink(), "fixture source refuses symlinks")
        relative = path.relative_to(original)
        require(relative.parts[0] not in {".git", ".audit"}, "fixture source includes runtime state")
        require(path.is_file() or path.is_dir(), "fixture source must be regular")
        if not path.is_file() or not any(relative.as_posix().startswith(root + "/") for root in roots):
            continue
        copied = source / relative
        copied.parent.mkdir(parents=True, exist_ok=True)
        raw = path.read_bytes()
        copied.write_bytes(raw)
        require(copied.read_bytes() == raw, "isolated fixture source bytes differ")
        files.add(relative.as_posix())
    require(files, "fixture source is empty")
    git_environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    for index, args in enumerate((
            ["init", "-q"], ["add", "--all"],
            ["commit", "-q", "-m", "source-owned reasoning controls"])):
        with (output / f"source-git-{index:02}.stdout.log").open("wb") as stdout, (output / f"source-git-{index:02}.stderr.log").open("wb") as stderr:
            done = subprocess.run([
                "git", "-c", "core.hooksPath=", "-c", "commit.gpgsign=false",
                "-c", "core.autocrlf=false",
                "-c", "user.name=Reasoning no-call control",
                "-c", "user.email=reasoning-no-call@example.invalid", *args],
                cwd=source, env=git_environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, check=False)
        require(done.returncode == 0, "isolated fixture Git preparation failed; original streams retained")
    return files


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
    original_source = corpus / "fixtures"
    require(original_source.is_dir() and not original_source.is_symlink(), "source-only fixture tree missing")
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
    budget = {"schema": "legion-reasoning-qualification-budget/1",
              "maxPhysicalAdmissions": MAX_CALLS, "perCallReservationTokens": PER_CALL_TOKENS,
              "reservationCeilingTokens": MAX_CALLS * PER_CALL_TOKENS, "width": 1,
              "strictNoRetry": True, "installedAuditPolicyChanged": False}
    (output / "qualification-budget.json").write_text(json.dumps(budget, sort_keys=True) + "\n")
    (output / "binary-retrieval-verification.json").write_bytes(args.readiness.read_bytes())
    for name in ("cases.json", "packet-plan.json"):
        (output / name).write_bytes((corpus / name).read_bytes())

    def ref(path):
        return {"path": str(prefix / path.relative_to(output).as_posix()),
                "sha256": sha(path.read_bytes())}

    capture = {"schema": "legion-reasoning-native-host-capture/2",
               "host": {"platform": "macos", "runtime": "claude-code",
                        "sessionId": os.environ["CLAUDE_CODE_SESSION_ID"]},
               "binary": identity, "commands": [], "exports": [], "members": [],
               "ledger": {"kind": "runner-owned-cumulative-admissions", "maxPhysicalAdmissions": MAX_CALLS,
                          "perCallReservationTokens": PER_CALL_TOKENS, "reservationCeilingTokens": MAX_CALLS * PER_CALL_TOKENS,
                          "width": 1, "retries": 0, "reclaims": 0,
                          "callIds": [], "admissionUnits": 0, "physicalCalls": 0,
                          "reservedTokens": 0, "actualUsageTokens": 0, "earmarkedTokens": 0},
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

    def command(role, argv, target_run, accepted=(0,), member=None):
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
                                    "stderr": ref(stderr), "run": str(target_run),
                                    "memberId": member["memberId"] if member else None})
        save()
        require(done.returncode in accepted, f"native {role} failed; original streams retained")
        return load(stdout), stdout

    try:
        cases = load(corpus / "cases.json")
        # Freeze every exact subset before any production model invocation.
        assigned = set()
        for index, providers in enumerate(MEMBER_PROVIDERS):
            member_id = f"run-{index + 1:02}"
            directory = output / member_id
            directory.mkdir()
            source = directory / "fixture-source"
            selected = [case for case in cases["cases"] if len(case["providerIds"]) == 1 and case["providerIds"][0] in providers]
            require(len(selected) == 2 * len(providers), "member paired controls differ")
            case_ids = sorted(case["caseId"] for case in selected)
            require(not assigned.intersection(case_ids), "member controls overlap")
            assigned.update(case_ids)
            roots = [case["fixtureRoot"].removeprefix("fixtures/") for case in selected]
            names = prepare_fixture_repository(original_source, source, directory, roots)
            files = {name: sha((source / name).read_bytes()) for name in sorted(names)}
            manifest = directory / "qualification-member.json"
            manifest.write_text(json.dumps({"schema": "legion-reasoning-qualification-member/1",
                "memberId": member_id, "memberIndex": index, "corpusRoot": str(corpus),
                "providerIds": list(providers), "caseIds": case_ids, "sourceRoot": str(source),
                "sourceFiles": files, "casesDigest": sha((corpus / "cases.json").read_bytes())}, sort_keys=True) + "\n")
            capture["members"].append({"memberId": member_id, "memberIndex": index,
                "providerIds": list(providers), "caseIds": case_ids, "sourceRoot": str(source),
                "run": str(directory / "native-run"), "sourceFiles": files,
                "manifest": ref(manifest), "preflight": None, "authorization": None, "checkpoint": None})
        require(assigned == {case["caseId"] for case in cases["cases"]}, "member union omits controls")
        save()
        command("preflight", ["audit", "check-reasoning-fixtures", "--root", str(corpus)], output)

        def prepare(member, run, quota, initial=False):
            require(not run.exists() and 0 < quota <= MAX_CALLS, "member run/quota must be fresh/bounded")
            argv = ["audit", member["sourceRoot"], "--json", "--coverage", "exhaustive",
                    "--seat-token-budget", str(PER_CALL_TOKENS), "--run-token-budget", str(quota * PER_CALL_TOKENS),
                    "--max-total-seats", str(quota), "--max-lens-seats", "1", "--out", str(run)]
            for provider in member["providerIds"] + ["security.misuse-resistance"]:
                argv.extend(["--only", provider])
            command("plan-preflight" if initial else "plan", argv, run, (0, 2), member)
            require(all((run / name).is_file() for name in ("plan.json", "execution.json", "report.json")),
                    "full production audit did not prepare execution evidence; original streams retain refusal")
            plan = load(run / "plan.json")
            require(plan["reviewContext"]["sourceRepository"] == member["sourceRoot"], "member audited source differs")
            snapshot = load(Path(plan["reviewContext"]["snapshotManifest"]))
            require(set(snapshot["files"]) == set(member["sourceFiles"]), "member frozen source subset differs")
            checked, path = command("dispatch-preflight" if initial else "dispatch",
                ["audit", "check-reasoning-dispatch", "--run", str(run)], run, member=member)
            require(checked["productionDispatchValidated"] is True and checked["modelCalls"] == 0
                    and checked["memberId"] == member["memberId"] and checked["remainingAdmissions"] == quota
                    and checked["expectedVerifierItems"] <= checked["verifierItemCap"] == 8,
                    "genuine member dispatch/verifier expectation preflight missing")
            return checked, ref(path)

        planned_authors = 0
        for member in capture["members"]:
            checked, member["preflight"] = prepare(member, Path(member["run"]).parent / "preflight-run", MAX_CALLS, True)
            planned_authors += checked["plannedAuthorSeats"]
            save()
        require(planned_authors + 3 <= MAX_CALLS, "planned authors plus fresh batch verifier reserves exceed shared quota")
        previous = None
        for member in capture["members"]:
            ledger = capture["ledger"]
            remaining = MAX_CALLS - ledger["admissionUnits"]
            run = Path(member["run"])
            checked, dispatch_ref = prepare(member, run, remaining)
            authorization = run.parent / "quota-authorization.json"
            authorization.write_text(json.dumps({"schema": "legion-reasoning-qualification-authorization/1",
                "memberId": member["memberId"], "manifest": member["manifest"], "remainingAdmissions": remaining,
                "tokenCeiling": remaining * PER_CALL_TOKENS, "previousCheckpoint": previous,
                "dispatchPreflight": dispatch_ref}, sort_keys=True) + "\n")
            member["authorization"] = ref(authorization)
            save()
            completed, _ = command("run", ["audit", "run-reasoning", "--run", str(run),
                "--strict-no-retry", "--max-calls-per-packet", "1"], run, (0, 2), member)
            require(completed.get("complete") is True and completed.get("status") == "done",
                    "member native runtime incomplete; no next member may start")
            pending, exports, call_ids = [run], [], []
            while pending:
                current = pending.pop(0)
                current_state_path = current / "next-state.json"
                if current_state_path.exists():
                    current_state = load(current_state_path)
                    require(not current_state.get("contextLimited")
                            and not current_state.get("continuationDigest")
                            and not current_state.get("historicalTerminalStatus"),
                            "member/follow-up contains context release or continuation history")
                verified, _ = command("verify", ["verify", str(current), "--json"], current, member=member)
                require(verified["valid"] is True and verified["runtimeCalls"]["status"] == "verified", "native authentication/accounting incomplete")
                exported, path = command("export", ["audit", "export-reasoning", "--run", str(current)], current, member=member)
                exports.append(ref(path))
                capture["exports"].append(ref(path))
                call_ids.extend(row["callId"] for row in exported["authenticatedCalls"])
                child = current / "followup"
                if child.exists():
                    require(current == run and child.is_dir() and not child.is_symlink(), "unexpected follow-up tree")
                    pending.append(child)
            state = load(run / "next-state.json")
            reservations = list(state["reservations"].values())
            admissions = state["issuances"]
            require(not state.get("contextLimited") and not state.get("continuationDigest")
                    and not state.get("historicalTerminalStatus") and not state.get("budgetBlocked") and not state.get("terminalStatus")
                    and admissions == len(reservations) and 0 < admissions <= remaining
                    and all(lease["attempts"] == 1 for lease in state["leases"].values()), "member stopped/released/reissued/unknown admission")
            authorized = [row for row in reservations if row["transportAuthorized"]]
            require(len(call_ids) == len(set(call_ids)) and set(call_ids) == {row["callId"] for row in authorized}
                    and not set(call_ids).intersection(ledger["callIds"]), "member native call/reservation mismatch or reuse")
            for row in reservations:
                require(row["retry"] is False and 0 < row["reservedTokens"] <= PER_CALL_TOKENS, "member reservation bounds differ")
                if row["transportAuthorized"]:
                    usage = row["usage"]
                    require(isinstance(usage, dict) and all(type(usage.get(key)) is int for key in
                        ("inputTokens", "outputTokens", "cachedInputTokens", "retryTokens"))
                        and usage["retryTokens"] == 0 and not usage["failed"]
                        and row["nativeCostRequired"] is True and row["reportedApiCostUsd"] is not None,
                        "member authenticated usage/cost incomplete")
            reserved = sum(row["reservedTokens"] for row in reservations)
            # Cached input is already included in inputTokens, counted once.
            actual_usage = sum(row["usage"]["inputTokens"] + row["usage"]["outputTokens"]
                          + row["usage"]["retryTokens"] for row in authorized)
            ledger["admissionUnits"] += admissions
            ledger["physicalCalls"] += len(call_ids)
            ledger["reservedTokens"] += reserved
            ledger["actualUsageTokens"] += actual_usage
            ledger["earmarkedTokens"] = ledger["admissionUnits"] * PER_CALL_TOKENS
            ledger["callIds"] = sorted(ledger["callIds"] + call_ids)
            require(ledger["admissionUnits"] <= MAX_CALLS and max(ledger["reservedTokens"], ledger["actualUsageTokens"], ledger["earmarkedTokens"])
                    <= MAX_CALLS * PER_CALL_TOKENS, "cumulative admission/token ceiling exceeded")
            checkpoint = run.parent / "checkpoint.json"
            checkpoint.write_text(json.dumps({"schema": "legion-reasoning-qualification-checkpoint/1",
                "memberId": member["memberId"], "authorization": member["authorization"], "remainingBefore": remaining,
                "admissionUnits": admissions, "physicalCalls": len(call_ids), "reservedTokens": reserved, "actualUsageTokens": actual_usage,
                "earmarkedTokens": admissions * PER_CALL_TOKENS,
                "remainingAfter": MAX_CALLS - ledger["admissionUnits"], "cumulativeAdmissions": ledger["admissionUnits"],
                "cumulativePhysicalCalls": ledger["physicalCalls"], "cumulativeReservedTokens": ledger["reservedTokens"],
                "cumulativeActualUsageTokens": ledger["actualUsageTokens"], "cumulativeEarmarkedTokens": ledger["earmarkedTokens"],
                "callIds": sorted(call_ids), "exports": exports}, sort_keys=True) + "\n")
            member["checkpoint"] = previous = ref(checkpoint)
            save()
    except Exception as error:
        save()
        (output / "capture-error.txt").write_text(str(error) + "\n")
        raise
    print(output / "capture.json")


if __name__ == "__main__":
    main()
