#!/usr/bin/env python3
"""Offline, bounded reasoning registration. Never runs a model or authenticates a host.

Source-owned maintainer observation/readback + authenticated CI artifact retrieval
are trust anchors. Native epoch MACs alone never establish external provenance.
Capture metadata is evidence to verify, never an authority that verifies itself.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

SELF = "scripts/ci/audit-reasoning-runtime-registration.py"
SCHEMA = "scripts/ci/schemas/audit-reasoning-native-host-capture.schema.json"
TEST = "scripts/ci/tests/test_audit_reasoning_runtime_registration.py"
FIXTURES = "scripts/ci/fixtures/audit-reasoning-runtime-accuracy"
SCOPE = "known-answer-fixture-cases"
FAMILY = "reasoning-runtime"
PROVIDERS = frozenset("reasoning." + name for name in (
    "doc-drift", "architecture", "correctness", "ai-slop", "naming", "dead-file", "schema", "security",
    "minimize", "performance", "a11y", "data-safety", "resilience", "platform-parity", "release-readiness")) | {
    "legacy.security.adjudication", "legacy.security.variant-analysis"}
ARCHIVE = "qualification/provider-accuracy/"
MEMBER_PROVIDERS = (
    ("reasoning.security", "legacy.security.adjudication", "legacy.security.variant-analysis",
     "reasoning.correctness", "reasoning.doc-drift", "reasoning.schema"),
    ("reasoning.architecture", "reasoning.minimize", "reasoning.naming", "reasoning.dead-file",
     "reasoning.performance", "reasoning.ai-slop"),
    ("reasoning.a11y", "reasoning.data-safety", "reasoning.resilience", "reasoning.platform-parity",
     "reasoning.release-readiness"),
)
CAPTURE_SCHEMA = "legion-reasoning-native-host-capture/2"
MEMBER_SCHEMA = "legion-reasoning-qualification-member/1"
AUTHORIZATION_SCHEMA = "legion-reasoning-qualification-authorization/1"
CHECKPOINT_SCHEMA = "legion-reasoning-qualification-checkpoint/1"
PER_CALL_TOKENS = 150000
MAX_ADMISSIONS = 44
MAX_RESERVED_TOKENS = PER_CALL_TOKENS * MAX_ADMISSIONS


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "reasoning fields differ")


def production_packet_bound(dispatch):
    require(isinstance(dispatch, dict), "native production dispatch absent")
    seats = dispatch.get("seats")
    require(isinstance(seats, list) and 0 < len(seats) <= 8
            and type(dispatch.get("requiredSeats")) is int and dispatch["requiredSeats"] == len(seats),
            "native production dispatch exceeds eight author packets or count differs")


def dispatch_preflight_evidence(preflight, dispatch):
    production_packet_bound(dispatch)
    require(preflight.get("dispatch") == dispatch and preflight.get("dispatchDigest") == digest(encoded(dispatch)),
            "native dispatch preflight/original production dispatch differs")


def dispatch_state_evidence(state, artifact):
    # Native next-state binds exact stored bytes with bare hex; preflight
    # separately binds parsed canonical JSON with its sha256: prefix.
    require(state.get("dispatchDigest") == artifact["sha256"].removeprefix("sha256:"),
            "budget state/frozen dispatch bytes differ")


def isolated_source_evidence(source_root, run, plan):
    require(Path(source_root) == Path(run).parent / "fixture-source"
            and plan.get("reviewContext", {}).get("sourceRepository") == source_root,
            "native isolated fixture source/plan differs")


def safe_absolute(value):
    require(isinstance(value, str) and value and Path(value).is_absolute(), "reasoning native path is not absolute")


def member_case_ids(controls, providers):
    return sorted(case["caseId"] for case in controls["cases"]
                  if case["providerIds"] and case["providerIds"][0] in providers)


def expected_member_sources(root, controls, providers):
    expected = {}
    for case in controls["cases"]:
        if not case["providerIds"] or case["providerIds"][0] not in providers:
            continue
        fixture = Path(root) / FIXTURES / case["fixtureRoot"]
        for path in fixture.rglob("*"):
            require(not path.is_symlink(), "reasoning member fixture symlink")
            if path.is_file():
                relative = path.relative_to(Path(root) / FIXTURES / "fixtures").as_posix()
                expected[relative] = digest(path.read_bytes())
    return dict(sorted(expected.items()))


def validate_member(root, controls, row, index, previous_checkpoint, retained_json):
    keys(row, {"memberId", "memberIndex", "providerIds", "caseIds", "sourceRoot", "run", "sourceFiles",
               "manifest", "preflight", "authorization", "checkpoint"})
    member_id = f"run-{index + 1:02d}"
    providers = list(MEMBER_PROVIDERS[index])
    safe_absolute(row["sourceRoot"]); safe_absolute(row["run"])
    require(row["memberId"] == member_id and row["memberIndex"] == index
            and row["providerIds"] == providers and row["caseIds"] == member_case_ids(controls, providers),
            "reasoning member partition/order differs")
    expected_sources = expected_member_sources(root, controls, providers)
    require(row["sourceFiles"] == expected_sources, "reasoning member source subset/hash differs")
    manifest = retained_json(row["manifest"])
    keys(manifest, {"schema", "memberId", "memberIndex", "corpusRoot", "providerIds", "caseIds", "sourceRoot", "sourceFiles", "casesDigest"})
    require(manifest == {"schema": MEMBER_SCHEMA, "memberId": member_id, "memberIndex": index,
                         "corpusRoot": str((Path(root) / FIXTURES).resolve()), "providerIds": providers,
                         "caseIds": row["caseIds"], "sourceRoot": row["sourceRoot"],
                         "sourceFiles": expected_sources,
                         "casesDigest": digest(source(root, FIXTURES + "/cases.json").read_bytes())},
            "frozen reasoning member manifest differs from source corpus")
    preflight_data = retained_json(row["preflight"])
    authorization = retained_json(row["authorization"])
    keys(authorization, {"schema", "memberId", "manifest", "remainingAdmissions", "tokenCeiling", "previousCheckpoint", "dispatchPreflight"})
    require(authorization["schema"] == AUTHORIZATION_SCHEMA and authorization["memberId"] == member_id
            and authorization["manifest"] == row["manifest"] and authorization["previousCheckpoint"] == previous_checkpoint,
            "reasoning member authorization binding differs")
    checkpoint = retained_json(row["checkpoint"])
    keys(checkpoint, {"schema", "memberId", "authorization", "remainingBefore", "admissionUnits", "physicalCalls",
                      "reservedTokens", "actualUsageTokens", "earmarkedTokens", "remainingAfter", "cumulativeAdmissions",
                      "cumulativePhysicalCalls", "cumulativeReservedTokens", "cumulativeActualUsageTokens",
                      "cumulativeEarmarkedTokens", "callIds", "exports"})
    require(checkpoint["schema"] == CHECKPOINT_SCHEMA and checkpoint["memberId"] == member_id
            and checkpoint["authorization"] == row["authorization"], "reasoning checkpoint/member authorization differs")
    return {"memberId": member_id, "providers": set(providers), "caseIds": set(row["caseIds"]),
            "sourceFiles": expected_sources, "manifest": row["manifest"], "preflight": row["preflight"],
            "preflightData": preflight_data,
            "authorization": row["authorization"], "authorizationData": authorization,
            "checkpoint": row["checkpoint"], "checkpointData": checkpoint, "run": row["run"],
            "sourceRoot": row["sourceRoot"], "index": index}


def native_accounting(value, calls):
    artifacts = {item["path"]: parsed(item["utf8"]) for item in value["artifacts"]}
    require("next-state.json" in artifacts and "lens-dispatch.json" in artifacts,
            "native root admission ledger/dispatch absent")
    state, dispatch = artifacts["next-state.json"], artifacts["lens-dispatch.json"]
    production_packet_bound(dispatch)
    dispatch_artifact = next(item for item in value["artifacts"] if item["path"] == "lens-dispatch.json")
    dispatch_state_evidence(state, dispatch_artifact)
    reservations = state.get("reservations")
    require(isinstance(reservations, dict) and type(state.get("issuances")) is int
            and state.get("issuances") == len(reservations) and state.get("budgetBlocked") == []
            and state.get("terminalStatus") in (None, "") and state.get("contextLimitedSeats", []) in ([], None)
            and state.get("contextLimited", []) in ([], None)
            and state.get("continuationDigest") in (None, "") and state.get("historicalTerminalStatus") in (None, "")
            and isinstance(state.get("leases"), dict)
            and all(type(lease.get("attempts")) is int and lease["attempts"] == 1 for lease in state["leases"].values()),
            "native admission state missing, released, terminal, resumed or reissued")
    authorized = {reservation.get("callId"): (reservation_id, reservation)
                  for reservation_id, reservation in reservations.items()
                  if reservation.get("transportAuthorized") is True}
    require(len(authorized) == sum(row.get("transportAuthorized") is True for row in reservations.values()),
            "native authorized call IDs duplicate")
    call_ids = [call["callId"] for call in calls]
    require(len(call_ids) == len(set(call_ids)) and set(call_ids) == set(authorized),
            "native exports do not cover exact original authorized calls")
    actual_tokens = 0
    for call in calls:
        reservation_id, reservation = authorized[call["callId"]]
        usage = call["observation"]["usage"]
        observation = call["observation"]
        require(reservation_id == call["authorization"].get("reservationId")
                and reservation.get("retry") is False and type(reservation.get("reservedTokens")) is int
                and 0 < reservation["reservedTokens"] <= PER_CALL_TOKENS
                and reservation.get("usage") == usage and usage.get("failed") is False
                and type(usage.get("inputTokens")) is int and type(usage.get("outputTokens")) is int
                and type(usage.get("retryTokens")) is int and usage["retryTokens"] == 0
                and all(type(usage.get(key)) is int and usage[key] >= 0
                        for key in ("inputTokens", "outputTokens", "cachedInputTokens", "retryTokens"))
                and reservation.get("nativeCostRequired") is True
                and isinstance(reservation.get("reportedApiCostUsd"), str)
                and len(reservation["reportedApiCostUsd"]) <= 128
                and re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?", reservation["reportedApiCostUsd"])
                and reservation["reportedApiCostUsd"] == observation.get("reportedApiEquivalentCostUsd")
                and usage["cachedInputTokens"] <= usage["inputTokens"]
                and type(reservation.get("outputTokenLimit")) is int
                and 0 <= usage["outputTokens"] <= reservation["outputTokenLimit"]
                and usage["inputTokens"] + usage["outputTokens"] + usage["retryTokens"] <= reservation["reservedTokens"],
                "native authorized usage/reservation reconciliation failed")
        actual_tokens += usage["inputTokens"] + usage["outputTokens"] + usage["retryTokens"]
    for reservation in reservations.values():
        require(reservation.get("retry") is False and type(reservation.get("reservedTokens")) is int
                and 0 < reservation["reservedTokens"] <= PER_CALL_TOKENS,
                "native reservation exceeds per-call ceiling or retries")
    reserved_tokens = sum(row["reservedTokens"] for row in reservations.values())
    require(isinstance(state.get("spent"), dict)
            and all(type(amount) is int and amount >= 0 for amount in state["spent"].values())
            and sum(state["spent"].values()) == reserved_tokens,
            "native reserved-token accounting differs from reservation inventory")
    require(max(reserved_tokens, actual_tokens) <= MAX_RESERVED_TOKENS,
            "native reservation/actual usage total exceeds cumulative ceiling")
    return {"admissionUnits": state["issuances"], "physicalCalls": len(call_ids),
            "reservedTokens": reserved_tokens, "actualUsageTokens": actual_tokens,
            "callIds": sorted(call_ids), "state": state, "artifacts": artifacts,
            "dispatch": dispatch}


def flag(argv, name):
    matches = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == name]
    require(len(matches) == 1, "native quota selector missing/duplicated")
    return matches[0]


def parsed(raw):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate reasoning JSON key")
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def source(root, relative):
    require(isinstance(relative, str) and len(relative) <= 240 and "\\" not in relative and ":" not in relative,
            "unsafe reasoning path")
    path = PurePosixPath(relative)
    require(path.parts and not path.is_absolute() and str(path) == relative and all(p not in (".", "..") for p in path.parts), "escaping reasoning path")
    current = Path(root)
    for part in path.parts:
        current /= part
        require(not current.is_symlink(), "reasoning symlink refused")
    require(current.is_file(), "missing reasoning evidence/source")
    return current


def reference(root, ref, category="evidence"):
    keys(ref, {"path", "sha256"})
    require(ref["path"].startswith(ARCHIVE + category + "/"), "reasoning evidence category differs")
    path = source(root, ref["path"])
    require(digest(path.read_bytes()) == ref["sha256"], "reasoning retained bytes changed")
    return path


def adapter(entry):
    require(entry["provider"] in PROVIDERS and entry["family"] == FAMILY and entry["stage"] == "finding"
            and entry["scope"] == SCOPE, "reasoning provider/stage/scope differs")
    return FAMILY, "native-reasoning-runtime", "canonical-json", None


def source_files(root):
    paths = {
        SELF, SCHEMA, TEST, "scripts/ci/audit-qualification-records.py", "qualification/provider-accuracy/schema.json",
        "src/registry/providers.json", "engine/Cargo.toml", "engine/Cargo.lock", "engine/rust-toolchain.toml",
        "scripts/ci/run-reasoning-native-qualification.py", ".rightgit.json", "package.json", "pnpm-lock.yaml",
        # Workspace manifests participate in Cargo resolution; only legion & its MCP path dependency add binary sources.
        "engine/bins/legion/Cargo.toml", "engine/bins/legion-mcp/Cargo.toml", "engine/bins/legion-dev/Cargo.toml",
        "engine/bins/legion-hook/Cargo.toml", "engine/xtask/Cargo.toml", "LICENSE",
        # Exact non-source include_str!/include_bytes! inputs of the native binary/dependency closure.
        "src/config/model-tiers.json", "skills/ios-development/config/tool-catalog.json",
        "engine/crates/legion-audit/assets/axe-core-4.14.0.min.js", "skills/audit/references/ponytail-lens.md",
        "scripts/ci/audit-jvm-sdk-inputs.json",
        "src/roster/sage.md", "src/roster/alchemist.md", "src/roster/alchemist-specialist.md",
        "src/roster/oracle.md", "src/roster/sentry.md", "doctrine/sage.md", "doctrine/alchemist.md",
        "doctrine/oracle.md", "doctrine/sentry.md", "doctrine/council-seat.md", "doctrine/legion.md",
    }
    for relative in ("engine/crates", "engine/bins/legion/src", "engine/bins/legion-mcp/src", "src/registry", FIXTURES):
        directory = Path(root) / relative
        require(directory.is_dir() and not directory.is_symlink(), "reasoning source root absent/unsafe")
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "reasoning source closure symlink")
            name = path.relative_to(root).as_posix()
            if path.is_file() and not re.fullmatch(r".*/\.audit/arcane/receipts/session-provenance/[0-9a-f]{64}\.json", name):
                # Native dependency sources/root build scripts + workspace manifests; omit test fixtures/build products.
                parts = path.relative_to(directory).parts
                if relative != "engine/crates" or (len(parts) == 2 and parts[1] == "Cargo.toml") or (
                        parts[0] != "legion-workspace-tests" and (
                            (len(parts) >= 3 and parts[1] == "src") or (len(parts) == 2 and parts[1] == "build.rs"))):
                    paths.add(name)
    for binary in ("engine/bins/legion", "engine/bins/legion-mcp"):
        build = Path(root) / binary / "build.rs"
        if build.exists():
            require(build.is_file() and not build.is_symlink(), "reasoning build script unsafe")
            paths.add(build.relative_to(root).as_posix())
    return sorted(paths)


def source_digest(root, relative):
    raw = source(root, relative).read_bytes()
    if relative == "src/registry/providers.json":
        value = parsed(raw)
        for row in value["providers"]:
            row.pop("benchmark", None)
        return digest(encoded(value))
    return digest(raw)


def qualification_fields():
    return {"productionQualification": False, "wholeProviderQualification": False, "auditCleanClaim": False,
            "fixtureScope": SCOPE, "negativeControlClaim": "known-answer FP=0; not native scoped_clean certification", "validationBasis": "observed-native-runtime-maintainer-readback",
            "coverageScope": "exact source-bound positive & clean fixture controls; no whole-repository claim"}


def actor(value, calls):
    require(isinstance(value, dict) and value.get("processCreated") is True and type(value.get("processId")) is int
            and value["processId"] > 0 and isinstance(value.get("contextId"), str) and value["contextId"]
            and isinstance(value.get("responseDigest"), str) and value["responseDigest"], "reasoning actor unobserved")
    matching = [call for call in calls if all(call["observation"].get(key) == value[key]
                for key in ("processId", "contextId", "responseDigest"))]
    require(len(matching) == 1, "reasoning actor has no unique authenticated call")
    return value["contextId"], value["processId"]


def accepted_result(request, artifacts):
    matches = [row["result"] for name, row in artifacts.items() if name.startswith("lens-receipts/")
               and row.get("result", {}).get("details", {}).get("executionReceipt", {}).get("requestId") == request["requestId"]]
    require(len(matches) == 1, "missing exact accepted native receipt")
    result = matches[0]
    receipt = result["details"]["executionReceipt"]
    bare = dict(result); bare["details"] = dict(result["details"]); bare["details"].pop("executionReceipt")
    require(result.get("complete") is True and result.get("coverageGaps") == [] and receipt.get("complete") is True
            and receipt.get("gaps") == [] and receipt.get("resultDigest") == digest(encoded(bare))
            and receipt.get("providerId") == request["providerId"] and receipt.get("planDigest") == request["planDigest"]
            and receipt.get("denominatorDigest") == request["denominatorDigest"], "accepted native result incomplete/unbound")
    return result


def staged_evidence(request, artifacts, calls, result, execution):
    details = result["details"]
    ledger = details.get("adjudicationLedger", {}).get("ledger", {})
    require(ledger.get("complete") is True and all(ledger.get(key) == [] for key in ("outstanding", "contested", "voidedBatches"))
            and all(isinstance(ledger.get(key), dict) and ledger[key].get("expected") == ledger[key].get("ingested")
                    for key in ("batches", "confirmations", "spotChecks", "individualReviews")), "canonical staged ledger incomplete")
    candidates = request["packet"].get("scannerCandidates", [])
    require(candidates and len({candidate["findingId"] for candidate in candidates}) == len(candidates), "staged candidates absent/duplicated")
    for candidate in candidates:
        require(candidate.get("provider") != "legacy.security.adjudication" and any(row.get("provider") == candidate.get("provider")
                and any(finding.get("id") == candidate["findingId"] for finding in row.get("result", {}).get("findings", []))
                for row in execution.get("results", [])), "candidate not produced by original native generator")
    submitted = details.get("rawAdjudicationVerdicts", [])
    observations = details.get("adjudicationDeliveryEvidence", [])
    require(submitted and observations, "native staged verdicts/observations absent")
    contexts, processes, bound_verdicts = set(), set(), set()
    for observation in observations:
        require(observation.get("kind") == "legion-adjudication-stage-observation" and observation.get("complete") is True
                and observation.get("truncated") is False, "staged delivery incomplete")
        host = {**observation, "contextId": observation.get("observedContextId")}
        context, pid = actor(host, calls)
        require(context not in contexts and pid not in processes, "staged contexts/processes reused")
        contexts.add(context); processes.add(pid)
        envelopes = [row for name, row in artifacts.items() if name.startswith("runtime-adjudication/")
                     and row.get("message", {}).get("requestId") == request["requestId"]
                     and row.get("message", {}).get("evidence", {}).get("observation") == observation]
        require(len(envelopes) == 1, "stage observation lacks original authenticated envelope")
        message = envelopes[0]["message"]
        require(message.get("kind") == "legion-audit-runtime-adjudication" and message.get("packetDigest") == digest(encoded(request["packet"])), "stage parent packet differs")
        stage = message["evidence"]["stagePacket"]
        require(stage in [row for name, row in artifacts.items() if name.startswith("adjudication/packets/")]
                and stage.get("kind") == "legion-audit-adjudication-seat"
                and observation.get("workItemId") == stage.get("itemId") and observation.get("stage") == stage.get("stage")
                and observation.get("workPacketDigest") == digest(encoded(stage["packet"]))
                and observation.get("deliveredPacketBytes") == len(encoded(stage["packet"])), "original staged child delivery differs")
        for candidate_id, verdict_digest in observation.get("verdictDigests", {}).items():
            matching = [verdict for verdict in submitted if verdict.get("candidateId") == candidate_id
                        and verdict.get("stage") == observation["stage"] and verdict.get("workItemId") == observation["workItemId"]
                        and digest(encoded(verdict)) == verdict_digest]
            require(len(matching) == 1 and any(matching[0] in row.get("verdicts", []) for name, row in artifacts.items()
                    if name.startswith("adjudication/results/")), "stage verdict absent from original result bytes")
            bound_verdicts.add(verdict_digest)
        for delivered in observation.get("sourceDelivery", []):
            require(any(candidate["findingId"] == delivered.get("candidateId") and candidate.get("path") == delivered.get("path")
                        and candidate.get("line") == delivered.get("startLine") for candidate in candidates), "staged source identity differs")
    require(bound_verdicts == {digest(encoded(verdict)) for verdict in submitted}, "staged verdict history unaccounted")
    final = details.get("securityVerdicts", [])
    for verdict in final:
        bare = {**verdict, "verdictDigest": ""}
        require(verdict.get("verdictDigest") == digest(encoded(bare)) and verdict.get("candidateProvider") != verdict.get("adjudicatorProvider")
                and verdict.get("adjudicatorProvider") == "legacy.security.adjudication", "final verdict independence/digest differs")
    for confirmed in details.get("securityConfirmed", []):
        require(any(verdict.get("candidateId") == confirmed.get("candidateId") and verdict.get("verdictDigest") == confirmed.get("verdictDigest")
                    and verdict.get("verdict") == confirmed.get("verdict") and verdict.get("domain") == "security"
                    and verdict.get("verdict") in {"TRUE_POSITIVE", "LIKELY_TRUE_POSITIVE"} for verdict in final)
                and any(row.get("stage") == "confirmation" and confirmed["candidateId"] in row.get("candidateIds", []) for row in observations), "confirmed parent lacks independent native confirmation")
    return [{"findingId": finding["id"], "authorFinding": finding, "evidence": [finding.get("anchor", {})]}
            for finding in details.get("lensFindings", [])]


def export_evidence(value):
    keys(value, {"schema", "run", "plan", "runtime", "authenticatedCalls", "packets", "ingested", "pending", "report", "execution", "artifacts",
                 "rawNativeStdoutRetained", "qualification", "productionQualification", "wholeProviderQualification"})
    require(value["schema"] == "legion-reasoning-runtime-export/1" and value["pending"] == []
            and all(value[key] is False for key in ("rawNativeStdoutRetained", "qualification", "productionQualification", "wholeProviderQualification")),
            "incomplete/expanded native export")
    require(isinstance(value["packets"], list) and value["packets"] and 0 < len(value["artifacts"]) <= 512, "missing native inventory")
    artifacts, total = {}, 0
    for item in value["artifacts"]:
        keys(item, {"path", "sha256", "bytes", "utf8"})
        path = PurePosixPath(item["path"])
        require(((len(path.parts) == 1 and item["path"] in {"next-state.json", "lens-dispatch.json"}) or (len(path.parts) == 2 and path.parts[0] in {"lens-packets", "lens-results", "runtime-author-results", "runtime-calls", "runtime-delivery", "runtime-verification", "runtime-adjudication", "lens-receipts"}) or (len(path.parts) == 3 and path.parts[:2] in {("adjudication", "packets"), ("adjudication", "results")}))
                and path.suffix == ".json" and path.name not in (".", "..") and item["path"] not in artifacts, "native artifact inventory differs")
        raw = item["utf8"].encode()
        require(type(item["bytes"]) is int and len(raw) == item["bytes"] and digest(raw) == item["sha256"], "native artifact bytes differ")
        total += len(raw)
        artifacts[item["path"]] = parsed(raw)
    require(total <= 64 * 1024 * 1024, "native artifact size exceeded")
    calls = value["authenticatedCalls"]
    require(isinstance(calls, list) and 0 < len(calls) <= MAX_ADMISSIONS, "native calls absent/exceeded")
    for call in calls:
        observation = call.get("observation", {})
        require(call.get("kind") == "legion-runtime-call" and call.get("strictNoRetry") is True
                and not call.get("repairOfCallId") and call.get("execution", {}).get("host") == "claude-code"
                and call.get("authorization", {}).get("authorized") is True and observation.get("sent") is True
                and observation.get("error") is None and observation.get("modelPolicyViolation") is None
                and observation.get("schemaRejection") is None and isinstance(observation.get("rawUsage"), dict)
                and observation["rawUsage"] and isinstance(observation.get("usage"), dict)
                and observation.get("physicalRequestDigest") == call.get("requestDigest"), "missing identity/usage/strict native call evidence")
        require(all(type(observation["usage"].get(key)) is int and observation["usage"][key] >= 0 for key in ("inputTokens", "outputTokens", "cachedInputTokens", "retryTokens"))
                and observation["usage"].get("failed") is False and observation["usage"]["retryTokens"] == 0, "unknown/failed/retry usage cannot qualify")
        require(any({key: val for key, val in item.items() if key != "authentication"} == call for name, item in artifacts.items()
                    if name.startswith("runtime-calls/")), "call absent from original authenticated inventory")
    packets = {}
    for item in value["packets"]:
        keys(item, {"packet", "authenticatedEvidence"})
        work, evidence = item["packet"], item["authenticatedEvidence"]
        request = work["request"]
        require(request["providerId"] == work["providerId"] and request["providerId"] in PROVIDERS
                and request["requestId"] not in packets, "native packet identity differs")
        require(work in [row for name, row in artifacts.items() if name.startswith("lens-packets/")], "packet absent from original inventory")
        accepted = accepted_result(request, artifacts)
        require(request["providerId"] in value["ingested"] and request["providerId"] not in value["execution"].get("pendingHost", []), "native provider not ingested/complete")
        native_results = [row["result"] for row in value["execution"].get("results", []) if row.get("provider") == request["providerId"] and row.get("skipped") is False]
        require(len(native_results) == 1 and native_results[0].get("complete") is True and native_results[0].get("coverageGaps") == [], "recomputed provider execution incomplete")
        if request["providerId"] == "legacy.security.adjudication":
            require(set(evidence) == {"delivery", "verification", "adjudication"}, "staged authenticated export fields differ")
            findings = staged_evidence(request, artifacts, calls, accepted, value["execution"])
            require(evidence["adjudication"] == accepted["details"]["adjudicationDeliveryEvidence"], "native stage accessor/result differs")
            packets[request["requestId"]] = {**item, "_acceptedResult": accepted, "_findings": findings}
            continue
        keys(evidence, {"delivery", "verification"})
        delivery, verification = evidence["delivery"], evidence["verification"]
        require(isinstance(delivery, dict) and isinstance(verification, dict)
                and delivery.get("complete") is True and delivery.get("truncated") is False
                and delivery.get("source") == "host-transport", "native delivery/verification missing")
        packet_digest = digest(encoded(request["packet"]))
        for name, proof in (("runtime-delivery", delivery), ("runtime-verification", verification)):
            require(proof.get("requestId") == request["requestId"] and proof.get("packetDigest") == packet_digest
                    and any(row.get("message", {}).get("evidence") == proof for path, row in artifacts.items() if path.startswith(name + "/")), "native proof/original packet binding differs")
        findings = verification.get("findings")
        require(isinstance(findings, list), "native verifier finding ledger absent")
        for row in findings:
            require(row.get("verdict") == "upheld" and row.get("findingDigest") == digest(encoded(row.get("authorFinding"))), "unresolved/contradicted fixture result")
            require(actor(row.get("author"), calls)[0] != actor(row.get("reviewer"), calls)[0]
                    and row["author"]["processId"] != row["reviewer"]["processId"], "reasoning verifier not fresh")
        if not findings:
            review = verification.get("negativeReview", {})
            require(review.get("verdict") == "scoped_clean" and review.get("contextComplete") is True
                    and review.get("anchorsVerified") is True and review.get("scope") == "supplied-frozen-packet"
                    and review.get("authorResult", {}).get("complete") is True, "negative control lacks complete independent challenge")
            require(actor(review.get("author"), calls)[0] != actor(review.get("reviewer"), calls)[0]
                    and review["author"]["processId"] != review["reviewer"]["processId"], "negative verifier not fresh")
        packets[request["requestId"]] = {**item, "_acceptedResult": accepted, "_findings": findings}
    for container in (value["execution"], value["report"]):
        require(all(isinstance(gap, str) and gap.startswith("provider-unqualified:") for gap in container.get("gaps", [])), "native outcome has nonqualification gap")
    require(value["report"].get("claims", {}).get("planDigest") == value["execution"].get("planDigest"), "native report/execution binding differs")
    return calls, packets


def validate(root, entry, record):
    adapter(entry)
    keys(record, {"schema", "provider", "family", "stage", "scope", "qualificationEligible", "productionQualification", "wholeProviderQualification", "auditCleanClaim", "cases", "qualificationDigest"})
    require(record["schema"] == "legion-reasoning-runtime-accuracy/1" and record["provider"] == entry["provider"]
            and record["family"] == FAMILY and record["stage"] == "finding" and record["scope"] == SCOPE
            and record["qualificationEligible"] is True and all(record[key] is False for key in ("productionQualification", "wholeProviderQualification", "auditCleanClaim")), "reasoning bounded record differs")
    keys(entry["provenance"], {"capture", "binaryRetrievalVerification"})
    retained = set()
    def retained_json(ref, category="evidence"):
        path = reference(root, ref, category)
        retained.add(ref["path"])
        return parsed(path.read_bytes())
    capture = retained_json(entry["provenance"]["capture"])
    keys(capture, {"schema", "host", "binary", "commands", "exports", "ledger", "cases", "packetPlan", "members"})
    require(capture["schema"] == CAPTURE_SCHEMA, "native host capture schema differs")
    keys(capture["host"], {"platform", "runtime", "sessionId"})
    require(capture["host"]["platform"] == "macos" and capture["host"]["runtime"] == "claude-code"
            and isinstance(capture["host"]["sessionId"], str) and capture["host"]["sessionId"], "genuine Claude Code host identity absent")
    binary = capture["binary"]
    keys(binary, {"sha256", "sourceCommit", "artifactId", "runId", "runAttempt", "jobId", "repository"})
    require(binary["repository"] == "Orthic-Labs/legion" and re.fullmatch(r"sha256:[0-9a-f]{64}", binary["sha256"])
            and re.fullmatch(r"[0-9a-f]{40}", binary["sourceCommit"])
            and all(type(binary[key]) is int and binary[key] > 0 for key in ("artifactId", "runId", "runAttempt", "jobId")), "CI-built binary identity absent")
    retrieval = retained_json(entry["provenance"]["binaryRetrievalVerification"], "verification")
    keys(retrieval, {"schema", "method", "verified", "binary", "artifactArchive", "jobLog", "sourceClosureDigest", "noCall"})
    require(retrieval["schema"] == "legion-reasoning-binary-retrieval-verification/1"
            and retrieval["method"] == "authenticated-github-artifact-retrieval" and retrieval["verified"] is True
            and retrieval["binary"] == binary and retrieval["sourceClosureDigest"] == entry["sourceClosure"]["digest"], "CI retrieval source binding absent")
    keys(retrieval["noCall"], {"verified", "sourceCommit", "binarySha256", "log"})
    require(retrieval["noCall"]["verified"] is True and retrieval["noCall"]["sourceCommit"] == binary["sourceCommit"]
            and retrieval["noCall"]["binarySha256"] == binary["sha256"], "exact CI-built binary no-call readback absent")
    reference(root, retrieval["noCall"]["log"]); retained.add(retrieval["noCall"]["log"]["path"])
    for key in ("artifactArchive", "jobLog"):
        reference(root, retrieval[key]); retained.add(retrieval[key]["path"])
    controls = parsed(source(root, FIXTURES + "/cases.json").read_bytes())
    require(controls["schema"] == "legion-reasoning-runtime-cases/1" and set(controls["providers"]) == PROVIDERS
            and len(controls["cases"]) == 34, "source-owned reasoning corpus differs")
    for key, filename in (("cases", "cases.json"), ("packetPlan", "packet-plan.json")):
        require(capture[key] == {"path": FIXTURES + "/" + filename, "sha256": digest(source(root, FIXTURES + "/" + filename).read_bytes())}, "capture corpus source binding differs")
    require(isinstance(capture["members"], list) and len(capture["members"]) == 3,
            "three frozen reasoning member manifests absent")
    members = [validate_member(root, controls, row, index,
                               capture["members"][index - 1]["checkpoint"] if index else None,
                               retained_json)
               for index, row in enumerate(capture["members"])]
    calls, runs, packets, export_refs, run_members = [], {}, {}, [], {}
    require(isinstance(capture["exports"], list) and len(capture["exports"]) >= 3, "native exports missing")
    for ref in capture["exports"]:
        value = retained_json(ref)
        current_calls, current_packets = export_evidence(value)
        require(value["run"] not in runs, "duplicate native run export")
        runs[value["run"]] = value
        run_members[value["run"]] = next((member["run"] for member in members
                                           if value["run"] == member["run"]
                                           or value["run"] == str(Path(member["run"]) / "followup")), None)
        require(run_members[value["run"]] is not None, "native export is not owned by a frozen member")
        for request_id, packet in current_packets.items():
            require(request_id not in packets, "duplicate request across run corpus")
            packets[request_id] = (value, packet)
        calls.extend(current_calls); export_refs.append(ref)
    require({packet["packet"]["providerId"] for _, packet in packets.values()} == PROVIDERS,
            "exact seventeen production providers not completed")
    require(isinstance(capture["commands"], list) and capture["commands"], "native commands absent")
    command_rows = capture["commands"]
    executable = command_rows[0]["argv"][0]
    allowed_roles = {"preflight", "plan-preflight", "dispatch-preflight", "plan", "dispatch", "run", "verify", "export"}
    role_rows = {}
    for position, command in enumerate(command_rows):
        keys(command, {"role", "memberId", "argv", "cwd", "environmentNames", "exitCode", "stdout", "stderr", "run"})
        role, argv, member_id = command["role"], command["argv"], command["memberId"]
        require(role in allowed_roles and isinstance(argv, list) and argv
                and all(isinstance(arg, str) and arg for arg in argv) and Path(argv[0]).is_absolute()
                and argv[0] == executable and command["cwd"] == str((Path(root) / FIXTURES).resolve())
                and Path(command["cwd"]).is_absolute() and Path(command["run"]).is_absolute()
                and type(command["exitCode"]) is int,
                "native command identity absent")
        require(member_id is None or member_id in {member["memberId"] for member in members}, "unknown native member command")
        names = command["environmentNames"]
        require(isinstance(names, list) and len(names) == len(set(names))
                and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names)
                and {"CLAUDECODE", "CLAUDE_CODE_SESSION_ID"} <= set(names)
                and not any(name.startswith("CODEX") for name in names), "native inherited identity names differ")
        for key in ("stdout", "stderr"):
            reference(root, command[key]); retained.add(command[key]["path"])
        require(command["exitCode"] == 0 or (role in {"plan-preflight", "plan", "run"} and command["exitCode"] == 2),
                "native stage failed")
        role_rows.setdefault((member_id, role), []).append((position, command))
    require(len(role_rows.get((None, "preflight"), [])) == 1 and command_rows[0]["role"] == "preflight"
            and command_rows[0]["memberId"] is None, "source-wide no-call preflight missing/reordered")
    expected_role_keys = {(None, "preflight")} | {
        (member["memberId"], role) for member in members
        for role in ("plan-preflight", "dispatch-preflight", "plan", "dispatch", "run", "verify", "export")
    }
    require(set(role_rows) == expected_role_keys, "native command stream contains missing or unassigned phases")
    first_run_position = min(position for (member_id, role), rows in role_rows.items() if role == "run" for position, _ in rows)
    require(all(position < first_run_position for (member_id, role), rows in role_rows.items()
                if role in {"plan-preflight", "dispatch-preflight"} for position, _ in rows),
            "all source/member dispatch preflights must precede any native call")
    preflight_command = command_rows[0]
    require(preflight_command["argv"][1:] == ["audit", "check-reasoning-fixtures", "--root", str((Path(root) / FIXTURES).resolve())],
            "source-owned corpus preflight selector differs")

    cumulative_admissions = cumulative_calls = cumulative_reserved = cumulative_actual = 0
    cumulative_call_ids, verified_runs, seen_exports = [], set(), []
    for member in members:
        member_id, index = member["memberId"], member["index"]
        providers = list(MEMBER_PROVIDERS[index])
        assigned = {role: rows for (mid, role), rows in role_rows.items() if mid == member_id}
        for role in ("plan-preflight", "dispatch-preflight", "plan", "dispatch", "run"):
            require(len(assigned.get(role, [])) == 1, "member native stage missing/duplicated")
        pre_plan = assigned["plan-preflight"][0][1]
        pre_dispatch = assigned["dispatch-preflight"][0][1]
        actual_plan = assigned["plan"][0][1]
        actual_dispatch = assigned["dispatch"][0][1]
        run_command = assigned["run"][0][1]
        require(assigned["plan-preflight"][0][0] < assigned["dispatch-preflight"][0][0]
                < assigned["plan"][0][0] < assigned["dispatch"][0][0] < assigned["run"][0][0],
                "native member prepare/dispatch/run phases reordered")
        require(pre_plan["run"] == str(Path(member["run"]).parent / "preflight-run")
                and actual_plan["run"] == member["run"] == run_command["run"]
                and pre_dispatch["run"] == pre_plan["run"] and actual_dispatch["run"] == member["run"],
                "native member run roots differ")
        for planned, quota in ((pre_plan, MAX_ADMISSIONS), (actual_plan, MAX_ADMISSIONS - cumulative_admissions)):
            argv = planned["argv"]
            expected_argv = ["audit", member["sourceRoot"], "--json", "--coverage", "exhaustive",
                             "--seat-token-budget", str(PER_CALL_TOKENS), "--run-token-budget", str(quota * PER_CALL_TOKENS),
                             "--max-total-seats", str(quota), "--max-lens-seats", "1", "--out", planned["run"]]
            for provider in providers + ["security.misuse-resistance"]:
                expected_argv.extend(["--only", provider])
            require(argv[1:] == expected_argv, "native member quota/coverage/provider planner differs")
        checks = []
        for command, expected_role, command_run in ((pre_dispatch, "dispatch-preflight", pre_plan["run"]),
                                                     (actual_dispatch, "dispatch", member["run"])):
            require(command["argv"][1:] == ["audit", "check-reasoning-dispatch", "--run", command_run],
                    "native dispatch-preflight selector differs")
            checked = parsed(reference(root, command["stdout"]).read_bytes())
            expected_review_count = len(providers)
            expected_zero_headroom = 2 if expected_review_count == 6 else 3
            require(checked.get("schema") == "legion-reasoning-runtime-dispatch-preflight/1"
                    and checked.get("run") == command_run and checked.get("memberIndex") == index
                    and checked.get("providerIds") == providers and checked.get("caseIds") == sorted(member["caseIds"])
                    and checked.get("productionDispatchValidated") is True and checked.get("modelCalls") == 0
                    and checked.get("qualification") is False and checked.get("memberId") == member_id
                    and checked.get("remainingAdmissions") == (MAX_ADMISSIONS if expected_role == "dispatch-preflight" else MAX_ADMISSIONS - cumulative_admissions)
                    and checked.get("expectedPlantedPositives") == expected_review_count
                    and checked.get("knownAnswerExpectedPositives") == expected_review_count
                    and checked.get("expectedPairedCleanControls") == expected_review_count
                    and checked.get("expectedVerifierItems") == expected_review_count
                    and checked.get("verifierItemCap") == 8
                    and checked.get("zeroFindingReviewHeadroom") == expected_zero_headroom
                    and type(checked.get("logicalPendingRequestCount")) is int
                    and 0 < checked["logicalPendingRequestCount"] <= 8
                    and checked.get("plannedFreshBatchVerifierAdmissions") == 1
                    and type(checked.get("plannedAuthorSeats")) is int and checked["plannedAuthorSeats"] > 0,
                    "native verifier/corpus dispatch preflight differs")
            require(isinstance(checked.get("planDigest"), str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", checked["planDigest"]),
                    "native dispatch preflight plan digest absent")
            dispatch_preflight_evidence(checked, checked.get("dispatch"))
            quota = MAX_ADMISSIONS if expected_role == "dispatch-preflight" else MAX_ADMISSIONS - cumulative_admissions
            dispatch = checked["dispatch"]
            require(checked["plannedAuthorSeats"] == dispatch["requiredSeats"]
                    and all(dispatch.get("reasoningBudget", {}).get(key) == value for key, value in
                            {"schemaVersion": 2, "totalTokens": quota * PER_CALL_TOKENS,
                             "perCallTokens": PER_CALL_TOKENS, "maxSeats": quota}.items())
                    and dispatch.get("limits", {}).get("waveWidth") == 1
                    and dispatch.get("withinLimits") is True and dispatch.get("boundedAudit") is False
                    and dispatch.get("coverageMode") == "exhaustive",
                    "native preflight production budget/coverage differs")
            checks.append(checked)
        require(member["preflight"]["path"] == pre_dispatch["stdout"]["path"]
                and member["preflight"]["sha256"] == pre_dispatch["stdout"]["sha256"],
                "frozen member preflight reference differs")
        remaining = MAX_ADMISSIONS - cumulative_admissions
        authorization = member["authorizationData"]
        previous_ref = members[index - 1]["checkpoint"] if index else None
        require(authorization["remainingAdmissions"] == remaining
                and authorization["tokenCeiling"] == remaining * PER_CALL_TOKENS
                and authorization["previousCheckpoint"] == previous_ref
                and authorization["dispatchPreflight"] == actual_dispatch["stdout"],
                "member quota authorization does not follow authenticated prior checkpoint")
        require(run_command["argv"][1:] == ["audit", "run-reasoning", "--run", member["run"],
                "--strict-no-retry", "--max-calls-per-packet", "1"], "native strict no-retry run selector differs")
        run_result = parsed(reference(root, run_command["stdout"]).read_bytes())
        require(run_result.get("complete") is True and run_result.get("status") == "done",
                "native member did not complete before next quota use")
        member_export_commands = [command for _, command in assigned.get("export", [])]
        member_verify_commands = [command for _, command in assigned.get("verify", [])]
        require(member_export_commands and len(member_verify_commands) == len(member_export_commands),
                "native parent/followup verification/export coverage differs")
        export_values, current_calls, current_packets = {}, [], {}
        member_refs = []
        for command in member_verify_commands:
            run_path = command["run"]
            require(run_path in runs and command["argv"][1:] == ["verify", run_path, "--json"],
                    "native verify tree selector/export missing")
            verification_output = parsed(reference(root, command["stdout"]).read_bytes())
            root_run = member["run"]
            require(verification_output.get("valid") is True
                    and verification_output.get("runtimeCalls", {}).get("status") == "verified"
                    and verification_output.get("runtimeCalls", {}).get("accountingRoot") == root_run,
                    "native parent/followup verification failed")
            verified_runs.add(run_path)
        for command in member_export_commands:
            run_path = command["run"]
            verify_positions = [position for position, row in assigned["verify"] if row["run"] == run_path]
            export_positions = [position for position, row in assigned["export"] if row["run"] == run_path]
            require(run_path in runs and command["argv"][1:] == ["audit", "export-reasoning", "--run", run_path]
                    and run_path in verified_runs and len(verify_positions) == len(export_positions) == 1
                    and assigned["run"][0][0] < verify_positions[0] < export_positions[0],
                    "native export lacks exact preceding verification")
            raw = reference(root, command["stdout"]).read_bytes()
            require(parsed(raw) == runs[run_path], "raw native stdout/export differs")
            export_ref = command["stdout"]
            member_refs.append(export_ref); seen_exports.append(export_ref)
            export_values[run_path] = runs[run_path]
            current, found = export_evidence(runs[run_path])
            current_calls.extend(current)
            for request_id, packet in found.items():
                require(request_id not in current_packets, "duplicate request within member exports")
                current_packets[request_id] = (runs[run_path], packet)
        require(member["run"] in export_values and set(export_values) == {command["run"] for command in member_export_commands}
                and set(export_values) == {command["run"] for command in member_verify_commands},
                "native member root/followup exports incomplete")
        if index:
            prior_end = max(position for role in ("verify", "export")
                            for position, _ in role_rows[(members[index - 1]["memberId"], role)])
            require(prior_end < assigned["plan"][0][0], "next member began before prior native tree was verified/exported")
        require(member["checkpointData"]["exports"] == member_refs, "member checkpoint export inventory differs")
        root_value = export_values[member["run"]]
        isolated_source_evidence(member["sourceRoot"], member["run"], root_value["plan"])
        accounting = native_accounting(root_value, current_calls)
        dispatch_preflight_evidence(checks[1], accounting["dispatch"])
        require(checks[1].get("planDigest") == root_value["plan"].get("seal", {}).get("digest")
                == root_value["plan"].get("nativePlan", {}).get("digest")
                and checks[1].get("planDigest") is not None
                and checks[1]["logicalPendingRequestCount"] == len(root_value["packets"]),
                "native dispatch preflight plan/logical packet binding differs")
        for run_path, run_value in export_values.items():
            require(run_members[run_path] == member["run"], "native command tree crosses frozen members")
            for item in run_value["artifacts"]:
                if item["path"] == "next-state.json":
                    state = parsed(item["utf8"])
                    require(not state.get("contextLimited") and not state.get("contextLimitedSeats")
                            and not state.get("continuationDigest") and not state.get("historicalTerminalStatus"),
                            "native followup state resumed or released context admission")
        require(set(current_packets) and {packet["packet"]["providerId"] for _, packet in current_packets.values()} == member["providers"],
                "member native exports do not cover exact frozen provider partition")
        cumulative_admissions += accounting["admissionUnits"]
        cumulative_calls += accounting["physicalCalls"]
        cumulative_reserved += accounting["reservedTokens"]
        cumulative_actual += accounting["actualUsageTokens"]
        cumulative_call_ids.extend(accounting["callIds"])
        checkpoint = member["checkpointData"]
        expected_checkpoint = {"remainingBefore": remaining, "admissionUnits": accounting["admissionUnits"],
            "physicalCalls": accounting["physicalCalls"], "reservedTokens": accounting["reservedTokens"],
            "actualUsageTokens": accounting["actualUsageTokens"],
            "earmarkedTokens": accounting["admissionUnits"] * PER_CALL_TOKENS,
            "remainingAfter": remaining - accounting["admissionUnits"],
            "cumulativeAdmissions": cumulative_admissions, "cumulativePhysicalCalls": cumulative_calls,
            "cumulativeReservedTokens": cumulative_reserved, "cumulativeActualUsageTokens": cumulative_actual,
            "cumulativeEarmarkedTokens": cumulative_admissions * PER_CALL_TOKENS,
            "callIds": accounting["callIds"]}
        require(all(checkpoint.get(key) == value for key, value in expected_checkpoint.items())
                and 0 < accounting["admissionUnits"] <= remaining
                and accounting["physicalCalls"] <= accounting["admissionUnits"],
                "native evidence does not support member checkpoint/quota transition")
        for run_value in export_values.values():
            for item in run_value["artifacts"]:
                if item["path"] == "lens-dispatch.json":
                    production_packet_bound(parsed(item["utf8"]))
    first_preflights = [parsed(reference(root, role_rows[(member["memberId"], "dispatch-preflight")][0][1]["stdout"]).read_bytes())
                        for member in members]
    require(sum(item["plannedAuthorSeats"] for item in first_preflights) + len(members) <= MAX_ADMISSIONS,
            "frozen author seats plus fresh verifier admissions exceed global ceiling")
    require(sorted(seen_exports, key=lambda ref: ref["path"]) == sorted(export_refs, key=lambda ref: ref["path"])
            and len({ref["path"] for ref in export_refs}) == len(export_refs)
            and verified_runs == set(runs), "native command/capture export inventory differs")
    require(0 < cumulative_admissions <= MAX_ADMISSIONS and cumulative_calls <= cumulative_admissions
            and max(cumulative_reserved, cumulative_actual, cumulative_admissions * PER_CALL_TOKENS) <= MAX_RESERVED_TOKENS
            and len(cumulative_call_ids) == len(set(cumulative_call_ids)), "cumulative native admission/token bound/reuse violated")
    ledger = capture["ledger"]
    keys(ledger, {"kind", "maxPhysicalAdmissions", "perCallReservationTokens", "reservationCeilingTokens", "width",
                  "retries", "reclaims", "callIds", "admissionUnits", "physicalCalls", "reservedTokens",
                  "actualUsageTokens", "earmarkedTokens"})
    require(ledger == {"kind": "runner-owned-cumulative-admissions", "maxPhysicalAdmissions": MAX_ADMISSIONS,
            "perCallReservationTokens": PER_CALL_TOKENS, "reservationCeilingTokens": MAX_RESERVED_TOKENS,
            "width": 1, "retries": 0, "reclaims": 0, "callIds": sorted(cumulative_call_ids),
            "admissionUnits": cumulative_admissions, "physicalCalls": cumulative_calls,
            "reservedTokens": cumulative_reserved, "actualUsageTokens": cumulative_actual,
            "earmarkedTokens": cumulative_admissions * PER_CALL_TOKENS},
            "runner-owned ledger differs from independently recomputed native evidence")
    packets = {request_id: pair for request_id, pair in packets.items()}
    calls = [call for value in runs.values() for call in export_evidence(value)[0]]
    wanted = [case for case in controls["cases"] if case["providerIds"] == [entry["provider"]]]
    require(len(wanted) == 2 and {next(iter(case["expected"])) for case in wanted} == {"positive", "negative"}, "positive/negative source controls absent")
    require(len(record["cases"]) == 2 and {case["caseId"] for case in record["cases"]} == {case["caseId"] for case in wanted}, "record controls incomplete")
    for result in record["cases"]:
        keys(result, {"caseId", "requestId", "run", "matched", "observedFindingIds"})
        expected = next(case for case in wanted if case["caseId"] == result["caseId"])
        require(result["matched"] is True and result["requestId"] in packets, "unexecuted case cannot qualify")
        value, packet = packets[result["requestId"]]
        request = packet["packet"]["request"]
        require(result["run"] == value["run"] and request["providerId"] == entry["provider"], "case/native request differs")
        fixture = Path(root) / FIXTURES / expected["fixtureRoot"]
        expected_paths = {path.relative_to(Path(root) / FIXTURES / "fixtures").as_posix() for path in fixture.rglob("*") if path.is_file()}
        require(expected_paths and expected_paths <= set(request["denominatorPaths"]), "case frozen production denominator omits fixture files")
        # Source-reviewed fixed groundtruth measures FP=0; it does not create
        # a native scoped_clean certificate for a fragment of a mixed packet.
        for relative in expected_paths:
            lines = source(root, FIXTURES + "/fixtures/" + relative).read_text().splitlines()
            require(any(excerpt.get("path") == relative and excerpt.get("mode") == "raw" and excerpt.get("startLine") == 1
                        and excerpt.get("truncated") is not True and not excerpt.get("redactedRanges")
                        and excerpt.get("content", "").splitlines() == lines for excerpt in request["packet"].get("excerpts", [])), "fixed control source not fully included in native packet")
        findings = packet["_findings"]
        observed = [row["findingId"] for row in findings if any(anchor.get("path", "").startswith(expected["fixtureRoot"].removeprefix("fixtures/") + "/")
                    for anchor in row.get("evidence", []) + [row.get("authorFinding", {}).get("anchor", {})])]
        require(sorted(result["observedFindingIds"]) == sorted(observed), "case observed finding inventory differs")
        if "positive" in expected["expected"]:
            require(observed, "planted defect not detected & independently upheld")
            for anchor in expected["expected"]["positive"]:
                full = expected["fixtureRoot"].removeprefix("fixtures/") + "/" + anchor["path"]
                lines = source(root, FIXTURES + "/fixtures/" + full).read_text().splitlines()
                require(0 < anchor["line"] <= len(lines) and lines[anchor["line"] - 1] == anchor["text"], "planted source anchor drift")
                require(any(any(item.get("path") == full and item.get("line") == anchor["line"] and item.get("text") == anchor["text"]
                            for item in row.get("evidence", []) + [row.get("authorFinding", {}).get("anchor", {})]) for row in findings), "positive native anchor differs")
        else:
            require(expected["expected"] == {"negative": {"noFindings": True}} and observed == [], "clean control has false positive")
        if entry["provider"] == "legacy.security.variant-analysis":
            followup, seeds = request["packet"].get("followup", {}), request["packet"].get("variantSeeds", [])
            owning_root = run_members[value["run"]]
            require(value["run"] != owning_root and value["plan"].get("followupOf", {}).get("kind") == "security-variant-analysis"
                    and followup.get("parentPlanDigest") == runs[owning_root]["plan"]["nativePlan"]["digest"] and seeds,
                    "variant lacks genuine confirmed-parent followup")
            parent_packet = next((item for parent_run, item in packets.values() if parent_run["run"] == owning_root and item["packet"]["providerId"] == "legacy.security.adjudication"), None)
            require(parent_packet is not None, "variant original adjudication parent absent")
            parent_details = parent_packet["_acceptedResult"]["details"]
            confirmed = parent_details.get("securityConfirmed", [])
            require(followup.get("confirmedDigest") == digest(encoded(confirmed))
                    and value["plan"]["followupOf"].get("confirmedDigest") == digest(encoded(confirmed))
                    and seeds and len(seeds) == len(confirmed), "variant confirmed-parent chain digest differs")
            for seed in seeds:
                matching = [row for row in confirmed if seed.get("candidateId") == row.get("candidateId")]
                require(len(matching) == 1 and seed.get("parentFindingId") == "adjudicated:" + matching[0]["candidateId"]
                        and all(seed.get(key) == matching[0].get(key) for key in ("path", "line", "verdict", "severity", "verdictDigest"))
                        and any(row["findingId"] == seed["parentFindingId"] for row in parent_packet["_findings"]), "variant seed not actual native confirmed parent")
            scope = request["packet"].get("variantScope", {})
            require(scope.get("rootCauseSearch", {}).get("status") == "examined-frozen-source-files"
                    and any(any(reason.startswith(("sibling-of:", "caller-of:", "root-cause-token:")) for reason in item.get("relations", []))
                            for item in scope.get("paths", [])), "variant sibling/root-cause scope not exercised")
    verified = retained_json(entry["provenanceVerification"], "verification")
    expected = {"schema": "legion-reasoning-native-host-provenance-verification/1", "method": "maintainer-observed-native-host-capture-and-authenticated-binary-retrieval",
                "verified": True, "captureSha256": entry["provenance"]["capture"]["sha256"], "binaryRetrievalVerificationSha256": entry["provenance"]["binaryRetrievalVerification"]["sha256"],
                "recordSha256": entry["record"]["sha256"], "sourceClosureDigest": entry["sourceClosure"]["digest"], "exportSha256": [ref["sha256"] for ref in export_refs],
                "ledgerDigest": digest(encoded(ledger)), "caseReadbackDigest": digest(encoded(record["cases"])),
                "allRequestedCoverageComplete": True, "authenticatedOutputsComplete": True, "independentVerificationComplete": True,
                "accountingComplete": True, "originalInventoryComplete": True, "stagedAdjudicationComplete": True,
                "globalQualificationOnlyExit2": any(command["exitCode"] == 2 for command in capture["commands"]), "productionQualification": False, "wholeProviderQualification": False}
    require(verified == expected, "missing source-owned maintainer observation/readback; local MACs do not authenticate provenance")
    return retained
