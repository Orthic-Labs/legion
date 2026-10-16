#!/usr/bin/env python3
"""Exercise bounded real-repository Audit planning against a pinned Ember tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


EMBER_URL = "https://github.com/Orthic-Labs/ember.git"
EMBER_REVISION = "9961562ed4c652b0bc6a9b3bc3a63142d885f583"
MAX_SECONDS = 120
FULL_AUDIT_MAX_SECONDS = 600
MAX_DIAGNOSTIC_CHARS = 6000
MAX_JSON_ARTIFACT_BYTES = 16 * 1024 * 1024
CODE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
    ".jsx", ".kt", ".m", ".mm", ".php", ".py", ".rb", ".rs", ".scala",
    ".swift", ".ts", ".tsx", ".vue",
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def diagnostic(text: str) -> str:
    if len(text) <= MAX_DIAGNOSTIC_CHARS:
        return text
    retained = MAX_DIAGNOSTIC_CHARS // 2
    omitted = len(text) - retained * 2
    return f"{text[:retained]}\n...[{omitted} characters omitted]...\n{text[-retained:]}"


def run(command: list[str], *, cwd: Path | None = None,
        env: dict[str, str] | None = None, timeout: int = MAX_SECONDS,
        allowed_returncodes: set[int] | frozenset[int] = frozenset({0})) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as error:
        stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
        fail(f"timed out after {timeout}s: {' '.join(command)}\n{diagnostic(stderr)}")
    if result.returncode not in allowed_returncodes:
        fail(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{diagnostic(result.stdout)}\nstderr:\n{diagnostic(result.stderr)}"
        )
    return result


def json_file(path: Path, *, bounded: bool = False) -> dict:
    try:
        metadata = path.lstat()
        if not path.is_file() or path.is_symlink():
            fail(f"expected regular non-symlink JSON artifact: {path}")
        if bounded and metadata.st_size > MAX_JSON_ARTIFACT_BYTES:
            fail(f"JSON artifact exceeds {MAX_JSON_ARTIFACT_BYTES} bytes: {path} ({metadata.st_size})")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read JSON artifact {path}: {error}")
    if not isinstance(value, dict):
        fail(f"expected JSON object in {path}")
    return value


def substantive_code_excerpt(excerpt: dict) -> bool:
    path = excerpt.get("path")
    content = excerpt.get("content")
    if not isinstance(path, str) or Path(path).suffix.lower() not in CODE_SUFFIXES:
        return False
    if excerpt.get("mode") not in {"raw", "regions"} or not isinstance(content, str):
        return False
    body_lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "/*", "*", "<!--")):
            continue
        body_lines.append(stripped)
    return len(body_lines) >= 3 and sum(map(len, body_lines)) >= 80


def validate_dispatch_budget(dispatch: dict) -> tuple[list[str], list[dict]]:
    expected_reasoning_budget = {
        "totalTokens": 50000,
        "perCallTokens": 10000,
        "outputTokens": 2500,
        "maxSeats": 5,
    }
    expected_limits = {
        "seatTokenBudget": 10000,
        "waveWidth": 1,
        "runTokenBudget": 50000,
        "maxTotalSeats": 5,
    }
    budget = dispatch.get("reasoningBudget")
    limits = dispatch.get("limits")
    if not isinstance(budget, dict) or any(budget.get(key) != value for key, value in expected_reasoning_budget.items()):
        fail(f"frozen reasoningBudget differs from requested caps: {budget!r}")
    if not isinstance(limits, dict) or any(limits.get(key) != value for key, value in expected_limits.items()):
        fail(f"frozen dispatch limits differ from requested caps: {limits!r}")

    seats = dispatch.get("seats")
    if not isinstance(seats, list) or not seats:
        fail("bounded dispatch has no selected author seats")
    provider_ids: set[str] = set()
    seat_receipts = []
    for seat in seats:
        if not isinstance(seat, dict):
            fail(f"selected physical seat is malformed: {seat!r}")
        providers = seat.get("providers")
        if not isinstance(providers, list) or not providers or any(not isinstance(item, str) for item in providers):
            fail(f"selected physical seat lacks provider IDs: {seat.get('seatId')!r}")
        provider_ids.update(providers)
        output_cap = seat.get("outputTokenLimit")
        output_ceiling = seat.get("outputTokenCeiling")
        allowance = seat.get("perCallTokenAllowance")
        input_bytes = seat.get("modelVisibleInputBytes")
        planned_input_bytes = seat.get("plannedModelInputBytes")
        estimate = seat.get("estimatedTokens")
        estimated_input = seat.get("estimatedInputTokens")
        if type(output_cap) is not int or not 1000 <= output_cap <= 2500:
            fail(f"selected physical seat has invalid adaptive output cap: {seat.get('seatId')!r}: {output_cap!r}")
        if type(output_ceiling) is not int or output_ceiling != 2500:
            fail(f"selected physical seat has unexpected output ceiling: {seat.get('seatId')!r}: {output_ceiling!r}")
        if allowance != 10000:
            fail(f"selected physical seat has unexpected per-call allowance: {seat.get('seatId')!r}: {allowance!r}")
        if type(input_bytes) is not int or input_bytes <= 0 or planned_input_bytes != input_bytes:
            fail(f"selected physical seat lacks positive matching model-input bytes: {seat.get('seatId')!r}")
        expected_input = (input_bytes + 1) // 2
        expected_estimate = expected_input + output_cap
        if estimated_input != expected_input or estimate != expected_estimate:
            fail(
                f"selected physical seat estimate differs from ceil(inputBytes/2)+outputCap: "
                f"{seat.get('seatId')!r}: inputBytes={input_bytes}, outputCap={output_cap}, "
                f"estimatedInput={estimated_input}, estimatedTotal={estimate}, expected={expected_estimate}"
            )
        if expected_estimate > 8500 or expected_estimate > allowance:
            fail(f"selected physical seat exceeds 8500-token planning headroom: {seat.get('seatId')!r}: {expected_estimate}")
        if seat.get("gatherPolicy") != "deterministic" or seat.get("initialPhysicalCalls") != 1:
            fail(f"selected physical seat is not one deterministic author call: {seat.get('seatId')!r}")
        seat_receipts.append({
            "seatId": seat.get("seatId"),
            "providerIDs": providers,
            "outputTokenCap": output_cap,
            "modelInputBytes": input_bytes,
            "estimatedInputTokens": estimated_input,
            "estimatedTotalTokens": estimate,
            "perCallTokenAllowance": allowance,
        })
    return sorted(provider_ids), seat_receipts


def checkout(destination: Path) -> None:
    destination.mkdir(parents=True)
    run(["git", "init", "--quiet", str(destination)])
    run(["git", "-C", str(destination), "remote", "add", "origin", EMBER_URL])
    run(["git", "-C", str(destination), "fetch", "--quiet", "--depth=1", "origin", EMBER_REVISION], timeout=60)
    run(["git", "-C", str(destination), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    actual = run(["git", "-C", str(destination), "rev-parse", "HEAD"]).stdout.strip()
    if actual != EMBER_REVISION:
        fail(f"Ember checkout mismatch: expected {EMBER_REVISION}, got {actual}")


def inspect_run(out: Path, *, plan_only: bool = True,
                persisted_gaps: set[str] | None = None,
                output_gaps: set[str] | None = None) -> dict:
    plan_path = out / "plan.json"
    dispatch_path = out / "lens-dispatch.json"
    plan = json_file(plan_path, bounded=not plan_only)
    dispatch = json_file(dispatch_path)
    if plan.get("kind") != "audit-provider-plan":
        fail(f"unexpected frozen plan kind: {plan.get('kind')!r}")
    if plan_only:
        if plan.get("auditStatus") != "incomplete":
            fail(f"plan-only audit has unexpected status: {plan.get('auditStatus')!r}")
        if plan.get("processExecution") != "not-run" or plan.get("processState") != "not-run":
            fail("plan-only gate unexpectedly reports provider execution")
    if dispatch.get("kind") != "legion-lens-dispatch":
        fail(f"unexpected dispatch artifact kind: {dispatch.get('kind')!r}")
    if dispatch.get("coverageMode") != "risk-sampled" or dispatch.get("boundedAudit") is not True:
        fail("dispatch did not freeze a bounded risk-sampled plan")
    if dispatch.get("withinLimits") is not True:
        fail(f"dispatch is over limits: {dispatch.get('violations')}")

    selected_provider_ids, selected_seats = validate_dispatch_budget(dispatch)
    seats = dispatch.get("seats")
    selected = dispatch.get("selectedPackets")
    if not isinstance(selected, list) or not selected:
        fail("bounded dispatch has no selected author packets")
    if len(selected) != len(set(selected)):
        fail("dispatch selected duplicate author packets")
    if any(seat.get("gatherPolicy") != "deterministic" for seat in seats):
        fail("dispatch contains non-deterministic evidence-gather policy")
    if dispatch.get("gatherCalls") != 0:
        fail(f"deterministic policy unexpectedly reserves gather calls: {dispatch.get('gatherCalls')}")
    if any(seat.get("evidenceGatherer") is not None for seat in seats):
        fail("dispatch unexpectedly includes a model-backed evidence gatherer")

    initial_calls = dispatch.get("requiredInitialCalls")
    reserve_calls = dispatch.get("followupReserveCalls")
    if not isinstance(initial_calls, int) or not isinstance(reserve_calls, int):
        fail("dispatch lacks physical call accounting")
    if initial_calls > 4 or reserve_calls != 1 or initial_calls + reserve_calls > 5:
        fail(f"physical call budget exceeded: initial={initial_calls}, reserve={reserve_calls}")
    if any(seat.get("initialPhysicalCalls") != 1 for seat in seats):
        fail("an author seat has unexpected physical-call count")

    packet_dir = out / "lens-packets"
    source_paths = set()
    substantive_sources = set()
    correctness_has_raw_code = False
    packet_provider_ids = set()
    excerpt_count = 0
    for name in selected:
        if not isinstance(name, str) or Path(name).name != name:
            fail(f"invalid selected packet path: {name!r}")
        path = packet_dir / name
        if not path.is_file():
            fail(f"selected author packet missing: {path}")
        work_item = json_file(path)
        request = work_item.get("request")
        if not isinstance(request, dict):
            fail(f"selected author packet lacks serialized request: {path}")
        packet = request.get("packet")
        if not isinstance(packet, dict):
            fail(f"selected author packet lacks request packet: {path}")
        provider_id = request.get("providerId")
        if not isinstance(provider_id, str) or packet.get("provider") != provider_id:
            fail(f"selected author packet has inconsistent provider identity: {path}")
        packet_provider_ids.add(provider_id)
        excerpts = packet.get("excerpts")
        if not isinstance(excerpts, list) or not excerpts:
            fail(f"selected author packet has no frozen source excerpts: {path}")
        excerpt_count += len(excerpts)
        source_paths.update(
            excerpt["path"] for excerpt in excerpts
            if isinstance(excerpt, dict) and isinstance(excerpt.get("path"), str)
        )
        substantive_sources.update(
            excerpt["path"] for excerpt in excerpts
            if isinstance(excerpt, dict) and substantive_code_excerpt(excerpt)
        )
        if provider_id == "reasoning.correctness" and any(
            excerpt.get("mode") == "raw" and substantive_code_excerpt(excerpt)
            for excerpt in excerpts if isinstance(excerpt, dict)
        ):
            correctness_has_raw_code = True
    if not source_paths:
        fail("selected author packets contain no source paths")
    if not substantive_sources:
        fail(f"selected author packets contain no substantive raw code excerpts; source paths={sorted(source_paths)}")
    if "reasoning.correctness" not in selected_provider_ids or "reasoning.correctness" not in packet_provider_ids:
        fail("bounded dispatch did not select the reasoning.correctness provider")
    if not correctness_has_raw_code:
        fail("selected reasoning.correctness packet lacks substantive raw code excerpts")
    if packet_provider_ids != set(selected_provider_ids):
        fail(f"selected packet providers differ from selected physical seats: packets={sorted(packet_provider_ids)}, seats={selected_provider_ids}")

    deferred = dispatch.get("deferredWork", [])
    deferred_packets = dispatch.get("deferredPackets", [])
    if not isinstance(deferred, list) or not isinstance(deferred_packets, list):
        fail("dispatch deferred-work fields are malformed")
    if plan_only:
        input_gaps = plan.get("inputGaps", [])
        if not isinstance(input_gaps, list):
            fail("frozen plan inputGaps field is malformed")
    else:
        if persisted_gaps is None or output_gaps is None:
            fail("full audit deferred-work validation requires persisted/output report gaps")
        input_gaps = persisted_gaps & output_gaps
    for work in deferred:
        if not isinstance(work, dict) or not all(work.get(key) for key in ("providerId", "packet", "reason")):
            fail(f"deferred work lacks explicit identity or reason: {work!r}")
        if work["packet"] not in deferred_packets:
            fail(f"deferred packet is absent from deferredPackets: {work['packet']}")
        expected_gap = f"lens-budget-deferred:{work['providerId']}:{work.get('part', 1)}:{work['reason']}"
        if expected_gap not in input_gaps:
            fail(f"deferred work lacks explicit frozen coverage gap {expected_gap!r}")

    performance = plan.get("sourcePerformance")
    if plan_only and not isinstance(performance, dict):
        fail("frozen plan lacks sourcePerformance cache statistics")
    excerpt_identity = []
    for name in selected:
        work_item = json_file(packet_dir / name)
        packet = work_item["request"]["packet"]
        excerpt_identity.extend(
            {
                "path": excerpt.get("path"),
                "anchors": excerpt.get("anchors"),
                "content": excerpt.get("content"),
            }
            for excerpt in packet["excerpts"]
        )
    excerpt_identity.sort(key=lambda item: (item["path"] or "", json.dumps(item["anchors"], sort_keys=True)))
    excerpt_digest = hashlib.sha256(
        json.dumps(excerpt_identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "dispatch": dispatch,
        "selected_provider_ids": selected_provider_ids,
        "selected_seats": selected_seats,
        "selected_count": len(selected),
        "source_count": len(source_paths),
        "substantive_source_count": len(substantive_sources),
        "excerpt_count": excerpt_count,
        "deferred_count": len(deferred),
        "source_performance": performance if isinstance(performance, dict) else {},
        "excerpt_digest": excerpt_digest,
    }


def validate_full_artifacts(out: Path, output: dict, returncode: int) -> dict:
    plan = json_file(out / "plan.json", bounded=True)
    facts = json_file(out / "facts.json", bounded=True)
    persisted = json_file(out / "report.json")
    if plan.get("kind") != "audit-provider-plan":
        fail(f"full audit persisted unexpected plan kind: {plan.get('kind')!r}")
    if output.get("kind") != "repository-audit-report":
        fail("full audit stdout is not a repository-audit-report")
    if facts.get("kind") != "audit-facts":
        fail(f"full audit persisted unexpected facts kind: {facts.get('kind')!r}")
    embedded_plan = facts.get("plan")
    if not isinstance(embedded_plan, dict):
        fail("full audit facts lack the embedded frozen plan")
    seal = plan.get("seal")
    embedded_seal = embedded_plan.get("seal")
    native_plan = plan.get("nativePlan")
    if not isinstance(seal, dict) or not isinstance(embedded_seal, dict) or not isinstance(native_plan, dict):
        fail("full audit plan or facts lack seal/native plan data")
    digest = seal.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:") or len(digest) != 71 or any(c not in "0123456789abcdef" for c in digest[7:]):
        fail(f"full audit plan has invalid or empty digest: {digest!r}")
    if embedded_seal.get("digest") != digest or native_plan.get("digest") != digest:
        fail("full audit facts embedded plan/native plan digest differs from persisted plan seal")
    if embedded_seal.get("signature") != seal.get("signature") or native_plan.get("signature") != seal.get("signature"):
        fail("full audit facts embedded plan/native plan signature differs from persisted plan seal")
    if not isinstance(persisted.get("findings"), list) or not isinstance(persisted.get("gaps"), list):
        fail("full audit persisted report lacks findings or gaps arrays")
    status = output.get("auditStatus")
    report_status = persisted.get("status")
    claims = persisted.get("claims")
    persisted_status = claims.get("auditStatus") if isinstance(claims, dict) else None
    if status not in {"pass", "findings", "incomplete"}:
        fail(f"full audit stdout has unexpected status: {status!r}")
    if report_status not in {"clean", "findings", "incomplete"}:
        fail(f"full audit persisted report has unexpected status: {report_status!r}")
    expected_status = "pass" if report_status == "clean" else report_status
    if status != expected_status or persisted_status != status:
        fail(f"full audit stdout/persisted status mismatch: stdout={status!r}, report={report_status!r}, claim={persisted_status!r}")
    if returncode == 2 and status not in {"findings", "incomplete"}:
        fail(f"full audit exited 2 without persisted findings or incomplete status: {status!r}")
    if returncode == 0 and status not in {"pass", "findings"}:
        fail(f"full audit exited 0 with unexpected status: {status!r}")
    if output.get("planDigest") != plan.get("seal", {}).get("digest"):
        fail("full audit stdout and persisted plan differ for planDigest")
    report_claims = persisted.get("claims")
    if not isinstance(report_claims, dict) or report_claims.get("planDigest") != digest:
        fail("full audit persisted report differs from persisted plan digest")
    if not isinstance(output.get("gaps"), list):
        fail("full audit stdout lacks report gaps")
    if any(not isinstance(gap, str) for gap in persisted["gaps"] + output["gaps"]):
        fail("full audit persisted or stdout report gaps are malformed")
    return {
        "status": status,
        "finding_count": len(persisted["findings"]),
        "gap_count": len(persisted["gaps"]),
        "facts_bytes": (out / "facts.json").stat().st_size,
        "plan_bytes": (out / "plan.json").stat().st_size,
        "report_bytes": (out / "report.json").stat().st_size,
        "persisted_gaps": set(persisted["gaps"]),
        "output_gaps": set(output["gaps"]),
        "dispatch": json_file(out / "lens-dispatch.json"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legion", required=True, type=Path)
    parser.add_argument("--provider-registry", required=True, type=Path)
    parser.add_argument("--runner-temp", required=True, type=Path)
    args = parser.parse_args()
    if not args.legion.is_file():
        fail(f"installed Legion CLI missing: {args.legion}")
    if not args.provider_registry.is_file():
        fail(f"installed provider registry missing: {args.provider_registry}")
    args.runner_temp.mkdir(parents=True, exist_ok=True)
    repo = args.runner_temp / "ember-bounded-checkout"
    if repo.exists():
        shutil.rmtree(repo)
    checkout(repo)
    exclude = repo / ".git" / "info" / "exclude"
    with exclude.open("a", encoding="utf-8") as handle:
        handle.write("\n.audit/\n")

    host_state = args.runner_temp / "ember-bounded-state"
    if host_state.is_symlink():
        fail(f"refusing to reset symlink state path: {host_state}")
    if host_state.exists():
        shutil.rmtree(host_state)
    host_state.mkdir(mode=0o700, parents=True)
    if os.name == "posix":
        os.chmod(host_state, 0o700)

    env = os.environ.copy()
    env["LEGION_PROVIDER_REGISTRY"] = str(args.provider_registry.resolve())
    env["LEGION_STATE_ROOT"] = str(host_state.resolve())
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"):
        env.pop(key, None)

    observations = []
    for label in ("cold", "warm"):
        out = repo / ".audit" / f"ember-bounded-{label}"
        command = [
            str(args.legion.resolve()), "audit", str(repo), "--plan-only",
            "--coverage", "risk-sampled", "--seat-token-budget", "10000",
            "--run-token-budget", "50000", "--max-total-seats", "5",
            "--max-lens-seats", "1", "--out", str(out), "--json",
        ]
        result = run(command, cwd=repo, env=env, allowed_returncodes={0, 2})
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            fail(
                f"audit did not return JSON ({error})\n"
                f"stdout:\n{diagnostic(result.stdout)}\nstderr:\n{diagnostic(result.stderr)}"
            )
        if not isinstance(output, dict) or output.get("kind") != "audit-provider-plan":
            fail(f"audit stdout is not an audit-provider-plan: {diagnostic(result.stdout)}")
        if output.get("auditStatus") != "incomplete":
            fail(f"audit stdout has unexpected status: {output.get('auditStatus')!r}")
        if output.get("processExecution") != "not-run" or output.get("processState") != "not-run":
            fail("audit stdout unexpectedly reports provider execution")
        try:
            observation = inspect_run(out)
        except RuntimeError as error:
            fail(f"{error}\naudit stderr:\n{diagnostic(result.stderr)}")
        persisted_plan = json_file(out / "plan.json")
        for key in ("planDigest", "planSignature", "repository"):
            if not output.get(key) or output.get(key) != persisted_plan.get(key):
                fail(f"audit stdout and persisted plan differ for {key}")
        if result.returncode == 2 and output.get("auditStatus") != "incomplete":
            fail("audit exited 2 without the expected incomplete plan-only status")
        observations.append((label, observation))

    if observations[0][1]["excerpt_digest"] != observations[1][1]["excerpt_digest"]:
        fail(
            "cold and warm passes selected different source excerpts: "
            f"{observations[0][1]['excerpt_digest']} != {observations[1][1]['excerpt_digest']}"
        )

    for label, observation in observations:
        dispatch = observation["dispatch"]
        print(json.dumps({
            "kind": "ember-bounded-audit-gate",
            "revision": EMBER_REVISION,
            "cachePass": label,
            "coverageMode": dispatch["coverageMode"],
            "selectedAuthorPackets": observation["selected_count"],
            "selectedProviderIDs": observation["selected_provider_ids"],
            "selectedSeats": observation["selected_seats"],
            "selectedSourcePaths": observation["source_count"],
            "substantiveCodeSourcePaths": observation["substantive_source_count"],
            "selectedSourceExcerpts": observation["excerpt_count"],
            "selectedSourceDigest": observation["excerpt_digest"],
            "deferredPackets": observation["deferred_count"],
            "initialPhysicalCalls": dispatch["requiredInitialCalls"],
            "freshReserveCalls": dispatch["followupReserveCalls"],
            "maximumPhysicalCalls": 5,
            "gatherPolicy": "deterministic",
            "withinLimits": dispatch["withinLimits"],
            "sourcePerformance": observation["source_performance"],
        }, sort_keys=True))

    out = repo / ".audit" / "ember-bounded-full"
    command = [
        str(args.legion.resolve()), "audit", str(repo),
        "--coverage", "risk-sampled", "--seat-token-budget", "10000",
        "--run-token-budget", "50000", "--max-total-seats", "5",
        "--max-lens-seats", "1", "--out", str(out), "--json",
    ]
    result = run(command, cwd=repo, env=env, timeout=FULL_AUDIT_MAX_SECONDS,
                 allowed_returncodes={0, 2})
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(
            f"full audit did not return JSON ({error})\n"
            f"stdout:\n{diagnostic(result.stdout)}\nstderr:\n{diagnostic(result.stderr)}"
        )
    if not isinstance(output, dict):
        fail(f"full audit stdout is not a JSON object: {diagnostic(result.stdout)}")
    try:
        full = validate_full_artifacts(out, output, result.returncode)
        observation = inspect_run(
            out, plan_only=False, persisted_gaps=full["persisted_gaps"],
            output_gaps=full["output_gaps"],
        )
    except RuntimeError as error:
        fail(f"{error}\nfull audit stderr:\n{diagnostic(result.stderr)}")
    dispatch = full["dispatch"]
    if dispatch.get("coverageMode") != "risk-sampled" or dispatch.get("boundedAudit") is not True:
        fail("full audit dispatch did not preserve bounded risk-sampled coverage")
    if dispatch.get("withinLimits") is not True:
        fail(f"full audit dispatch is over limits: {dispatch.get('violations')}")
    if observation["selected_count"] == 0 or observation["substantive_source_count"] == 0:
        fail("full audit did not retain substantive selected source packets")
    print(json.dumps({
        "kind": "ember-bounded-audit-gate",
        "revision": EMBER_REVISION,
        "cachePass": "full",
        "execution": "full-deterministic-audit",
        "coverageMode": dispatch["coverageMode"],
        "auditStatus": full["status"],
        "selectedAuthorPackets": observation["selected_count"],
        "selectedProviderIDs": observation["selected_provider_ids"],
        "selectedSeats": observation["selected_seats"],
        "selectedSourcePaths": observation["source_count"],
        "substantiveCodeSourcePaths": observation["substantive_source_count"],
        "selectedSourceExcerpts": observation["excerpt_count"],
        "selectedSourceDigest": observation["excerpt_digest"],
        "deferredPackets": observation["deferred_count"],
        "plannedInitialPhysicalCalls": dispatch["requiredInitialCalls"],
        "plannedFreshVerificationReserveCalls": dispatch["followupReserveCalls"],
        "plannedMaximumPhysicalCalls": 5,
        "actualModelCalls": 0,
        "gatherPolicy": "deterministic",
        "withinLimits": dispatch["withinLimits"],
        "planBytes": full["plan_bytes"],
        "factsBytes": full["facts_bytes"],
        "reportBytes": full["report_bytes"],
        "findings": full["finding_count"],
        "gaps": full["gap_count"],
        "sourcePerformance": observation["source_performance"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"audit-ember-bounded: {error}", file=sys.stderr)
        sys.exit(1)
