#!/usr/bin/env python3
"""Managed-CI capsule materialization & native plan-only projection; no models."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath

SOURCE_ALLOWANCE, ASSESSOR_ALLOWANCE, SEAT_ALLOWANCE = 40000, 10000, 10000
LIMITS = {"seatTokenBudget": 10000, "waveWidth": 1, "runTokenBudget": 40000, "maxTotalSeats": 3}
RESERVATIONS = ("requiredInitialCalls", "gatherCalls", "followupReserveCalls",
                "initialCallReservationTokens", "followupReserveTokens")
MANDATORY_CAPSULES = {
    "core.json": {
        ("core-doc-drift-retries", "doc-drift", "reasoning.doc-drift"),
        ("core-architecture-domain-ui", "architecture", "reasoning.architecture"),
        ("core-correctness-shipping-boundary", "correctness", "reasoning.correctness"),
        ("core-ai-slop-comment", "ai-slop", "reasoning.ai-slop"),
        ("core-naming-boolean-prefix", "naming", "reasoning.naming"),
        ("core-dead-file-unreferenced-module", "dead-file", "reasoning.dead-file"),
        ("core-schema-integer-cents", "schema", "reasoning.schema"),
    },
    "conditional.json": {
        ("conditional-minimize-rounding-strategy", "minimize", "reasoning.minimize"),
        ("conditional-performance-batched-order-query", "performance", "reasoning.performance"),
        ("conditional-a11y-checkout-action", "a11y", "reasoning.a11y"),
        ("conditional-data-safety-orders-migration", "data-safety", "reasoning.data-safety"),
        ("conditional-resilience-child-process", "resilience", "reasoning.resilience"),
        ("conditional-platform-parity-workspace", "platform-parity", "reasoning.platform-parity"),
        ("conditional-release-sign-before-upload", "release-readiness", "reasoning.release-readiness"),
    },
}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_path(value):
    return (isinstance(value, str) and bool(value) and "\\" not in value and ":" not in value and "\0" not in value
            and not PurePosixPath(value).is_absolute()
            and all(part not in ("", ".", "..") for part in value.split("/")))


def valid_window(row, files):
    if not isinstance(row, dict):
        return False
    path, bounds = row.get("path"), row.get("lineRange")
    return (path in files and isinstance(bounds, list) and len(bounds) == 2
            and all(type(n) is int for n in bounds)
            and 1 <= bounds[0] <= bounds[1] <= len(files[path].splitlines()))


def load_corpus(root):
    registry = json.loads((root / "src/registry/providers.json").read_bytes())
    specs = {spec["id"]: spec for spec in registry["providers"]}
    cases, bindings, capsules, lenses, ids = [], [], set(), set(), set()
    capsule_paths = sorted((root / "evals/audit-bench/capsules").glob("*.json"))
    names = {path.name for path in capsule_paths}
    require(set(MANDATORY_CAPSULES).issubset(names), "mandatory core/conditional capsule files missing")
    require(names.issubset(set(MANDATORY_CAPSULES) | {"security.json"}),
            "unexpected capsule file cannot substitute for a reviewed optional provider")
    security_included = "security.json" in names
    for path in capsule_paths:
        require(path.is_file() and not path.is_symlink(), "capsule must be a regular file")
        raw = path.read_bytes()
        document = json.loads(raw)
        require(document.get("schema") == "legion-audit-capsules/1"
                and document.get("constructed") is True, "invalid constructed corpus schema")
        bindings.append({"path": str(path.relative_to(root)), "digest": sha(raw)})
        file_identities = set()
        for entry in document["capsules"]:
            identity, lens, provider = (entry.get(key) for key in ("id", "lens", "providerId"))
            require(all(isinstance(v, str) and v for v in (identity, lens, provider)), "invalid capsule identity")
            require(identity not in capsules and lens not in lenses and provider == "reasoning." + lens,
                    "duplicate capsule/lens or incorrect provider binding")
            require(provider in specs and lens in specs[provider]["lensIds"], "provider absent from shipped registry")
            file_identities.add((identity, lens, provider))
            contract = entry.get("contract")
            require((isinstance(contract, str) and bool(contract.strip())) or
                    (isinstance(contract, dict) and isinstance(contract.get("invariant"), str)
                     and bool(contract["invariant"].strip())), "invalid capsule contract")
            capsules.add(identity)
            lenses.add(lens)
            pair = entry["cases"]
            require(len(pair) == 2 and {c["kind"] for c in pair} == {"planted", "clean"}, "invalid control pair")
            for case in pair:
                require(isinstance(case["id"], str) and case["id"] and case["id"] not in ids, "duplicate case id")
                ids.add(case["id"])
                files = case["files"]
                require(isinstance(files, dict) and files and all(safe_path(p) and isinstance(t, str)
                        for p, t in files.items()), "invalid fixture source files")
                expected = case["expected"]
                require(isinstance(expected, list) and bool(expected) == (case["kind"] == "planted"), "invalid expected controls")
                require(isinstance(case["forbiddenClaims"], list), "missing forbidden claims")
                require(all(valid_window(row, files) and row.get("claim") and row.get("severity")
                            for row in expected), "invalid expected finding window")
                evidence = case.get("requiredEvidence", [])
                require(isinstance(evidence, list) and all(valid_window(row, files)
                        and row.get("role") in ("contract", "caller", "behavior") for row in evidence), "invalid evidence window")
                if isinstance(contract, dict):
                    require(isinstance(contract.get("supportingFiles"), list)
                            and all(p in files for p in contract["supportingFiles"])
                            and isinstance(contract.get("reachableCallers"), list), "invalid contract source references")
                cases.append({"capsuleId": identity, "lens": lens, "providerId": provider, "case": case,
                              "nativeContract": specs[provider]["runner"]["contract"]})
        if path.name in MANDATORY_CAPSULES:
            require(file_identities == MANDATORY_CAPSULES[path.name],
                    f"mandatory capsule identities differ in {path.name}")
        else:
            require(path.name == "security.json" and file_identities and len(file_identities) == 1
                    and next(iter(file_identities)) == ("core-security-invoice-tenant-isolation",
                                                         "security", "reasoning.security")
                    and {case["id"] for entry in document["capsules"] for case in entry["cases"]}
                    == {"invoice-tenant-lookup-a", "invoice-tenant-lookup-b"},
                    "optional security file must contain the reviewed reasoning.security control pair")
    expected_capsules = 14 + int(security_included)
    require(len(capsules) == expected_capsules and len(cases) == expected_capsules * 2,
            "mandatory pairs or optional security pair are incomplete")
    return cases, bindings, security_included


def projection(files, expected, evidence, excerpts):
    gaps, rows, windows = [], [], []
    by_path = {path: [] for path in files}
    for excerpt in excerpts:
        require(isinstance(excerpt, dict) and excerpt.get("path") in files, "unexpected excerpt source")
        path, text = excerpt["path"], excerpt.get("content")
        lo, hi = excerpt.get("startLine"), excerpt.get("endLine")
        lines = files[path].splitlines()
        require(isinstance(text, str) and type(lo) is int and type(hi) is int
                and 1 <= lo <= hi <= len(lines) and excerpt.get("mode") in ("raw", "skeleton", "regions"),
                "invalid native excerpt bounds/content/mode")
        source = lines[lo - 1:hi]
        actual = text.splitlines()
        full = source == actual
        if excerpt.get("mode") == "raw" and not full:
            gaps.append({"kind": "raw-excerpt-source-mismatch", "path": path, "lineRange": [lo, hi]})
        # Skeleton anchors include collapsed bodies. Only exact unique text
        # matches get lower-bound line credit; bounds alone never prove bytes.
        retained = set(range(lo, hi + 1)) if full else {
            lo + i for i, line in enumerate(source)
            if source.count(line) == 1 and actual.count(line) == 1}
        by_path[path].append((excerpt, retained, full))
    for path, text in sorted(files.items()):
        parts = by_path[path]
        if not parts:
            gaps.append({"kind": "source-not-in-excerpts", "path": path})
        retained = set().union(*(part[1] for part in parts)) if parts else set()
        rows.append({"path": path, "sourceDigest": sha(text.encode()), "sourceLines": len(text.splitlines()),
                     "exactRetainedLinesLowerBound": len(retained),
                     "lineCoverageLowerBound": len(retained) / max(1, len(text.splitlines())),
                     "excerpts": [{"mode": e.get("mode"), "startLine": e["startLine"], "endLine": e["endLine"],
                                   "contentDigest": sha(e["content"].encode()), "contentBytes": len(e["content"].encode()),
                                   "fullWindowText": full, "redacted": e.get("redacted"), "anchors": e.get("anchors")}
                                  for e, _, full in parts]})
    if not {"contract", "caller", "behavior"}.issubset({row["role"] for row in evidence}):
        gaps.append({"kind": "required-contract-caller-or-behavior-evidence-unproven"})
    for row in evidence + [dict(row, role="expected-finding") for row in expected]:
        path, (lo, hi) = row["path"], row["lineRange"]
        source_lines = files[path].splitlines()
        wanted = source_lines[lo - 1:hi]
        proven = set()
        for excerpt, retained, full in by_path[path]:
            proven.update(retained if full else ())
            start, end = excerpt["startLine"], excerpt["endLine"]
            original, actual = source_lines[start - 1:end], excerpt["content"].splitlines()
            occurrences = lambda lines: sum(lines[i:i + len(wanted)] == wanted for i in range(len(lines) - len(wanted) + 1))
            if start <= lo <= hi <= end and occurrences(original) == occurrences(actual) == 1:
                proven.update(range(lo, hi + 1))
        present = all(n in proven for n in range(lo, hi + 1))
        windows.append({"role": row["role"], "path": path, "lineRange": [lo, hi], "textRetained": present,
                        "sourceTextDigest": sha("\n".join(wanted).encode())})
        if not present:
            gaps.append({"kind": "required-evidence-text-not-projected", "role": row["role"], "path": path, "lineRange": [lo, hi]})
    return rows, windows, gaps


def inspect_plan(plan, run, item, return_code):
    provider, lens = item["providerId"], item["lens"]
    # Native plan-only deliberately reports incomplete (exit 2): source
    # projection is not model execution or a completed audit.
    require(return_code == 2 and plan["kind"] == "audit-provider-plan"
            and plan["auditStatus"] == "incomplete" and plan["qualityGate"] == "unproven"
            and plan["completionValidation"] == plan["processExecution"] == plan["processState"] == "not-run"
            and plan["gaps"] == ["plan-only"],
            "native output is not plan-only")
    require(plan["providers"] == [provider] and plan["coverageMode"] == "exhaustive", "native provider/coverage scope differs")
    require(not plan["inputGaps"] and not [g for g in plan["gaps"] if g != "plan-only"], "native plan input gaps")
    dispatch, work = plan["lensDispatch"], plan["lensWork"]
    require(dispatch["limits"] == LIMITS and dispatch["withinLimits"] is True
            and not dispatch["violations"] and not dispatch["deferredWork"], "native dispatch invalid or deferred")
    require([w["provider"] for w in work] == [provider] and work[0]["lensIds"] == [lens], "lens work scope differs")
    require(work[0]["deferredParts"] == 0 and work[0]["selectedParts"] == work[0].get("partsTotal", 1), "packet parts deferred")
    seats = dispatch["seats"]
    require(seats and all(s["providers"] == [provider] and s["lensIds"] == [lens]
            and s["perCallTokenAllowance"] == SEAT_ALLOWANCE
            and type(s["outputTokenLimit"]) is int and 0 < s["outputTokenLimit"] <= s["outputTokenCeiling"] <= 2500
            for s in seats), "invalid physical seat bounds/scope")
    require(all(type(dispatch[key]) is int and dispatch[key] >= 0 for key in RESERVATIONS), "missing serialized reservation")
    require(dispatch["requiredSeats"] == len(seats) and dispatch["gatherCalls"] == 0
            and dispatch["requiredInitialCalls"] == sum(s["initialPhysicalCalls"] for s in seats)
            and dispatch["followupReserveCalls"] == 1
            and dispatch["initialCallReservationTokens"] == dispatch["requiredInitialCalls"] * SEAT_ALLOWANCE
            and dispatch["followupReserveTokens"] == dispatch["followupReserveCalls"] * SEAT_ALLOWANCE,
            "serialized reservation mismatch")
    excerpts, packets, packet_gaps = [], [], []
    for part in work[0].get("parts", [work[0]]):
        path = Path(part["packet"])
        require(not path.is_symlink() and path.resolve().is_relative_to(run), "packet outside run")
        raw = path.read_bytes()
        envelope = json.loads(raw)
        request, packet = envelope["request"], envelope["request"]["packet"]
        require(envelope["providerId"] == request["providerId"] == packet["provider"] == provider
                and envelope["lensIds"] == [lens] and packet["lensPlan"]["lens"] == lens,
                "packet provider/lens differs")
        require(packet["kind"] == "legion-reasoning-packet"
                and request["contract"] == packet["contract"] == item["nativeContract"], "packet contract differs")
        require(request["planDigest"] == packet["binding"]["planDigest"] == plan["planDigest"]
                and sha(encoded(packet)) == part["packetDigest"], "packet plan/digest differs")
        coverage = packet["excerptCoverage"]
        for field, kind in (("omittedPaths", "source-omitted"), ("truncatedPaths", "source-truncated")):
            require(isinstance(coverage[field], list), "invalid excerpt coverage")
            packet_gaps.extend({"kind": kind, "source": value, "packet": str(path.relative_to(run))}
                               for value in coverage[field])
        excerpts.extend(packet["excerpts"])
        packets.append({"file": str(path.relative_to(run)), "digest": sha(raw), "packetDigest": part["packetDigest"],
                        "contract": packet["contract"], "lens": packet["lensPlan"]["lens"]})
    keys = (*RESERVATIONS, "limits", "seats", "packetBytes", "modelVisibleInputBytes", "seatReadBytes",
            "unsharedRequestBytes", "physicalRequestBytesSaved", "withinLimits")
    return {key: dispatch[key] for key in keys}, excerpts, packets, packet_gaps


def write_fixture_sources(source, files):
    hashes = {path: sha(text.encode("utf-8")) for path, text in sorted(files.items())}
    for relative, text in files.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = text.encode("utf-8")
        target.write_bytes(raw)
        require(not target.is_symlink() and target.is_file() and target.read_bytes() == raw
                and sha(raw) == hashes[relative], "fixture source bytes differ after materialization")
    return hashes


def initialize_fixture_git(source, hashes):
    """Give each source-only fixture a fresh local Git baseline without rewriting inputs."""
    hooks = source.parent / (source.name + "-disabled-hooks")
    hooks.mkdir(parents=False, exist_ok=False)
    environment = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                   "GIT_AUTHOR_NAME": "Legion capsule preflight", "GIT_AUTHOR_EMAIL": "capsule-preflight@localhost",
                   "GIT_COMMITTER_NAME": "Legion capsule preflight", "GIT_COMMITTER_EMAIL": "capsule-preflight@localhost"}

    def git(*args):
        completed = subprocess.run(["git", "-C", str(source), *args], cwd=source,
                                   env=environment, capture_output=True, check=False, shell=False)
        require(completed.returncode == 0,
                "fixture Git baseline failed: " + completed.stderr.decode("utf-8", "replace"))
        return completed.stdout

    git("init", "--quiet")
    git("add", "--all")
    git("-c", f"core.hooksPath={hooks}", "commit", "--quiet", "-m", "source-owned capsule fixture")
    tracked = {path.decode("utf-8") for path in git("ls-files", "-z").split(b"\0") if path}
    require(tracked == set(hashes), "fixture Git baseline tracked-file set differs")
    for relative, expected in hashes.items():
        target = source / relative
        require(not target.is_symlink() and target.is_file() and sha(target.read_bytes()) == expected,
                "fixture Git baseline changed source bytes")
        require(sha(git("show", f"HEAD:{relative}")) == expected,
                "fixture Git commit does not preserve source bytes")


def run_case(root, legion, out, number, item):
    case, gaps = item["case"], []
    source, run = out / "fixtures" / f"{number:04}", out / "runs" / f"{number:04}"
    source.mkdir(parents=True, exist_ok=False)
    run.mkdir(parents=True, exist_ok=False)
    hashes = write_fixture_sources(source, case["files"])
    initialize_fixture_git(source, hashes)
    command = [str(legion), "audit", str(source), "--only", item["providerId"], "--plan-only", "--out", str(run),
               "--coverage", "exhaustive", "--seat-token-budget", "10000", "--run-token-budget", "40000",
               "--max-lens-seats", "1", "--max-total-seats", "3", "--json"]
    dispatch, packets, projected, windows = {}, [], [], []
    try:
        completed = subprocess.run(command, cwd=root, capture_output=True, timeout=120, check=False, shell=False)
        stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
        plan_path = run / "plan.json"
        require(not plan_path.is_symlink(), "plan artifact symlink")
        dispatch, excerpts, packets, packet_gaps = inspect_plan(json.loads(plan_path.read_bytes()), run, item, code)
        gaps.extend(packet_gaps)
        projected, windows, projection_gaps = projection(case["files"], case["expected"], case.get("requiredEvidence", []), excerpts)
        gaps.extend(projection_gaps)
    except subprocess.TimeoutExpired as error:
        stdout, stderr, code = error.stdout or b"", error.stderr or b"", None
        gaps.append({"kind": "native-plan-timeout", "timeoutSeconds": 120})
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
        stdout, stderr, code = locals().get("stdout", b""), locals().get("stderr", b""), locals().get("code")
        gaps.append({"kind": "native-plan-or-projection-invalid", "detail": str(error)})
    for path, expected_hash in hashes.items():
        if (source / path).is_symlink() or sha((source / path).read_bytes()) != expected_hash:
            gaps.append({"kind": "fixture-source-changed", "path": path})
    (run / "stdout.bin").write_bytes(stdout)
    (run / "stderr.bin").write_bytes(stderr)
    return {"caseId": case["id"], "capsuleId": item["capsuleId"], "providerId": item["providerId"], "lens": item["lens"],
            "kind": case["kind"], "sourceRoot": str(source), "sourceFiles": hashes, "sourceDigest": sha(encoded(hashes)),
            "command": command, "returnCode": code, "stdoutDigest": sha(stdout), "stderr": stderr.decode("utf-8", "replace"),
            "failureStdout": stdout.decode("utf-8", "replace") if code != 0 else None,
            "dispatch": dispatch, "packets": packets, "projectedContentCoverage": projected, "requiredWindows": windows,
            "preflightGaps": gaps, "status": "ready" if not gaps else "unproven", "modelCalls": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "legion", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": "legion-audit-capsule-preflight/1", "modelCalls": 0, "generationAuthorized": False,
              "claimBoundary": "Plan-only source projection; no authenticated model delivery, semantic review or accuracy claim."}
    try:
        require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_TEMP"), "managed CI required")
        root, legion, out = args.root.resolve(strict=True), args.legion.resolve(strict=True), args.out.resolve()
        require(out.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve())
                and not out.is_relative_to(root), "output must be under RUNNER_TEMP outside checkout")
        require(legion.is_file() and os.access(legion, os.X_OK), "native binary unavailable")
        items, bindings, security_included = load_corpus(root)
        out.mkdir(parents=True, exist_ok=True)
        cases = report["cases"] = []
        for i, item in enumerate(items, 1):
            try:
                cases.append(run_case(root, legion, out, i, item))
            except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
                cases.append({"caseId": item["case"]["id"], "providerId": item["providerId"], "dispatch": {},
                    "status": "unproven", "modelCalls": 0,
                    "preflightGaps": [{"kind": "case-materialization-or-readback-invalid", "detail": str(error)}]})
        complete = all(case["status"] == "ready" for case in cases)
        priced = [case["dispatch"] for case in cases if case["dispatch"]]
        tokens = sum(d["initialCallReservationTokens"] + d["followupReserveTokens"] for d in priced)
        calls = sum(d["requiredInitialCalls"] + d["followupReserveCalls"] for d in priced)
        report.update({"status": "ready" if complete else "unproven", "corpusFiles": bindings,
            "corpusDigest": sha(encoded(bindings)), "caseCount": len(cases), "cases": cases,
            "reservation": {"scope": f"these {len(items)} independent source plans only; tally is not additional admission",
                "pricedCases": len(priced), "aggregateRequiredSourceReservationTokens": tokens,
                "aggregateRequiredSourceCalls": calls, "existingSourceAllowanceTokens": SOURCE_ALLOWANCE,
                "existingSourceAdmissions": 4, "fitsExistingSourceAllowance": len(priced) == len(items) and tokens <= SOURCE_ALLOWANCE and calls <= 4,
                "assessorAllowanceTokens": ASSESSOR_ALLOWANCE, "assessorSeparate": True,
                "allowanceChanged": False, "automaticSpend": False},
            "unpricedRemainingProviders": (["legacy.security.adjudication", "legacy.security.variant-analysis"]
                if security_included else ["reasoning.security", "legacy.security.adjudication", "legacy.security.variant-analysis"]),
            "preflightGaps": [{"caseId": c["caseId"], "gap": g} for c in cases for g in c["preflightGaps"]]})
        (out / "capsule-preflight.json").write_bytes(encoded(report) + b"\n")
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
        report.update({"status": "unproven", "preflightGaps": [{"kind": "corpus-or-preflight-invalid", "detail": str(error)}]})
    print("CAPSULE_PREFLIGHT " + encoded(report).decode(), flush=True)
    return 0 if report["status"] == "ready" else 1


if __name__ == "__main__":
    sys.exit(main())
