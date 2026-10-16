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
MAX_DIAGNOSTIC_CHARS = 6000
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


def json_file(path: Path) -> dict:
    try:
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


def checkout(destination: Path) -> None:
    destination.mkdir(parents=True)
    run(["git", "init", "--quiet", str(destination)])
    run(["git", "-C", str(destination), "remote", "add", "origin", EMBER_URL])
    run(["git", "-C", str(destination), "fetch", "--quiet", "--depth=1", "origin", EMBER_REVISION], timeout=60)
    run(["git", "-C", str(destination), "checkout", "--quiet", "--detach", "FETCH_HEAD"])
    actual = run(["git", "-C", str(destination), "rev-parse", "HEAD"]).stdout.strip()
    if actual != EMBER_REVISION:
        fail(f"Ember checkout mismatch: expected {EMBER_REVISION}, got {actual}")


def inspect_run(out: Path) -> dict:
    plan_path = out / "plan.json"
    dispatch_path = out / "lens-dispatch.json"
    if not plan_path.is_file():
        fail(f"frozen plan missing: {plan_path}")
    if not dispatch_path.is_file():
        fail(f"lens dispatch plan missing: {dispatch_path}")
    plan = json_file(plan_path)
    dispatch = json_file(dispatch_path)
    if plan.get("kind") != "audit-provider-plan":
        fail(f"unexpected frozen plan kind: {plan.get('kind')!r}")
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

    seats = dispatch.get("seats")
    if not isinstance(seats, list) or not seats:
        fail("bounded dispatch has no selected author seats")
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
    if not source_paths:
        fail("selected author packets contain no source paths")
    if not substantive_sources:
        fail(f"selected author packets contain no substantive raw code excerpts; source paths={sorted(source_paths)}")

    deferred = dispatch.get("deferredWork", [])
    deferred_packets = dispatch.get("deferredPackets", [])
    if not isinstance(deferred, list) or not isinstance(deferred_packets, list):
        fail("dispatch deferred-work fields are malformed")
    input_gaps = plan.get("inputGaps", [])
    if not isinstance(input_gaps, list):
        fail("frozen plan inputGaps field is malformed")
    for work in deferred:
        if not isinstance(work, dict) or not all(work.get(key) for key in ("providerId", "packet", "reason")):
            fail(f"deferred work lacks explicit identity or reason: {work!r}")
        if work["packet"] not in deferred_packets:
            fail(f"deferred packet is absent from deferredPackets: {work['packet']}")
        expected_gap = f"lens-budget-deferred:{work['providerId']}:{work.get('part', 1)}:{work['reason']}"
        if expected_gap not in input_gaps:
            fail(f"deferred work lacks explicit frozen coverage gap {expected_gap!r}")

    performance = plan.get("sourcePerformance")
    if not isinstance(performance, dict):
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
        "selected_count": len(selected),
        "source_count": len(source_paths),
        "substantive_source_count": len(substantive_sources),
        "excerpt_count": excerpt_count,
        "deferred_count": len(deferred),
        "source_performance": performance,
        "excerpt_digest": excerpt_digest,
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
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(f"audit-ember-bounded: {error}", file=sys.stderr)
        sys.exit(1)
