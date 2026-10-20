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
    require(isinstance(calls, list) and 0 < len(calls) <= 44, "native calls absent/exceeded")
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
    keys(capture, {"schema", "host", "binary", "commands", "exports", "ledger", "cases", "packetPlan"})
    require(capture["schema"] == "legion-reasoning-native-host-capture/1", "native host capture schema differs")
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
    calls, runs, packets, export_hashes = [], {}, {}, []
    require(isinstance(capture["exports"], list) and capture["exports"], "native exports missing")
    for ref in capture["exports"]:
        value = retained_json(ref)
        current_calls, current_packets = export_evidence(value)
        require(value["run"] not in runs, "duplicate native run export")
        runs[value["run"]] = value
        for request_id, packet in current_packets.items():
            require(request_id not in packets, "duplicate request across run corpus")
            packets[request_id] = (value, packet)
        calls.extend(current_calls); export_hashes.append(ref["sha256"])
    require({packet["packet"]["providerId"] for _, packet in packets.values()} == PROVIDERS, "exact seventeen production providers not completed")
    call_ids = [call["callId"] for call in calls]
    require(len(call_ids) == len(set(call_ids)) and 0 < len(calls) <= 44, "cumulative physical admission cap/reuse violated")
    ledger = capture["ledger"]
    keys(ledger, {"rootRun", "maxPhysicalAdmissions", "perCallReservationTokens", "reservationCeilingTokens", "width", "retries", "reclaims", "callIds", "reservedTokens"})
    require(ledger["rootRun"] in runs and ledger["maxPhysicalAdmissions"] == 44 and ledger["perCallReservationTokens"] == 10000
            and ledger["reservationCeilingTokens"] == 440000 and ledger["width"] == 1 and ledger["retries"] == ledger["reclaims"] == 0
            and ledger["callIds"] == sorted(call_ids) and ledger["reservedTokens"] == 10000 * len(calls), "cumulative production reservation ledger differs")
    root_artifacts = {item["path"]: parsed(item["utf8"]) for item in runs[ledger["rootRun"]]["artifacts"]}
    require("next-state.json" in root_artifacts and "lens-dispatch.json" in root_artifacts, "original cumulative budget state/dispatch absent")
    state, dispatch = root_artifacts["next-state.json"], root_artifacts["lens-dispatch.json"]
    production_packet_bound(dispatch)
    dispatch_artifact = next(item for item in runs[ledger["rootRun"]]["artifacts"] if item["path"] == "lens-dispatch.json")
    dispatch_state_evidence(state, dispatch_artifact)
    reservations = state.get("reservations")
    require(isinstance(reservations, dict) and type(state.get("issuances")) is int and len(calls) <= state["issuances"] <= 44
            and state.get("budgetBlocked") == [] and all(lease.get("attempts") == 1 for lease in state.get("leases", {}).values()), "unknown/reissued/unaccounted physical reservation")
    authorized = {key: row for key, row in reservations.items() if row.get("transportAuthorized") is True}
    require(sorted(row.get("callId") for row in authorized.values()) == sorted(call_ids), "parent/followup cumulative call inventory differs")
    for call in calls:
        reservation = reservations.get(call["authorization"].get("reservationId"), {})
        require(reservation.get("callId") == call["callId"] and reservation.get("transportAuthorized") is True
                and reservation.get("retry") is False and reservation.get("reservedTokens") == 10000
                and reservation.get("usage") == call["observation"]["usage"], "full physical reservation/usage not reconciled")
    roles, exported, verified_runs = set(), [], set()
    require(isinstance(capture["commands"], list) and capture["commands"], "native commands absent")
    require([row["role"] for row in capture["commands"][:4]] == ["preflight", "plan", "dispatch", "run"]
            and all(row["role"] in {"verify", "export"} for row in capture["commands"][4:]), "native source/plan/dispatch must precede first generation")
    executable = capture["commands"][0]["argv"][0]
    for command in capture["commands"]:
        keys(command, {"role", "argv", "cwd", "environmentNames", "exitCode", "stdout", "stderr", "run"})
        role, argv = command["role"], command["argv"]
        require(role in {"preflight", "plan", "dispatch", "run", "verify", "export"} and isinstance(argv, list) and argv
                and all(isinstance(arg, str) and arg for arg in argv) and Path(argv[0]).is_absolute()
                and argv[0] == executable and Path(command["cwd"]).is_absolute() and type(command["exitCode"]) is int, "native command identity absent")
        names = command["environmentNames"]
        require(isinstance(names, list) and len(names) == len(set(names)) and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in names)
                and {"CLAUDECODE", "CLAUDE_CODE_SESSION_ID"} <= set(names) and not any(name.startswith("CODEX") for name in names), "native inherited identity names differ")
        for key in ("stdout", "stderr"):
            reference(root, command[key]); retained.add(command[key]["path"])
        require(command["exitCode"] == 0 or (role in {"plan", "run"} and command["exitCode"] == 2), "native stage failed")
        if role == "preflight":
            require(len(argv) == 5 and argv[1:4] == ["audit", "check-reasoning-fixtures", "--root"], "native source preflight selector differs")
        if role == "plan":
            require(len(argv) == 52 and argv[1] == "audit"
                    and argv[3:16] == ["--json", "--coverage", "exhaustive", "--seat-token-budget", "10000", "--run-token-budget", "440000", "--max-total-seats", "44", "--max-lens-seats", "1", "--out", command["run"]]
                    and argv[16::2] == ["--only"] * 18 and set(argv[17::2]) == PROVIDERS | {"security.misuse-resistance"}, "native frozen planner selector differs")
            require(command["run"] == ledger["rootRun"], "native initial plan/accounting root differs")
            isolated_source_evidence(argv[2], command["run"], runs[ledger["rootRun"]]["plan"])
        if role == "dispatch":
            preflight = parsed(reference(root, command["stdout"]).read_bytes())
            dispatch_preflight_evidence(preflight, dispatch)
            require(preflight.get("schema") == "legion-reasoning-runtime-dispatch-preflight/1"
                    and preflight.get("productionDispatchValidated") is True and preflight.get("modelCalls") == 0
                    and preflight.get("qualification") is False and preflight.get("run") == command["run"], "native frozen dispatch preflight absent")
            require(command["run"] == ledger["rootRun"] and argv[1:] == ["audit", "check-reasoning-dispatch", "--run", command["run"]], "native dispatch preflight selector differs")
        if role == "verify":
            require(command["run"] in runs and argv[1:] == ["verify", command["run"], "--json"], "native verify selector differs")
            verification_output = parsed(reference(root, command["stdout"]).read_bytes())
            require(verification_output.get("valid") is True and verification_output.get("runtimeCalls", {}).get("status") == "verified"
                    and verification_output.get("runtimeCalls", {}).get("accountingRoot") == ledger["rootRun"]
                    and verification_output.get("runtimeCalls", {}).get("count") == len(calls)
                    and verification_output.get("runtimeCalls", {}).get("nativeReservationCount") == len(calls), "native verify output not valid/authenticated")
            verified_runs.add(command["run"])
        if role == "run":
            require(command["run"] == ledger["rootRun"] and argv[1:] == ["audit", "run-reasoning", "--run", command["run"], "--strict-no-retry", "--max-calls-per-packet", "1"], "native strict runtime selector differs")
        if role == "export":
            require(argv[1:] == ["audit", "export-reasoning", "--run", command["run"]] and command["run"] in verified_runs, "native export selector differs")
            raw = reference(root, command["stdout"]).read_bytes()
            require(parsed(raw) == runs[command["run"]], "raw native stdout/export differs")
            exported.append(command["stdout"]["sha256"])
        roles.add(role)
    require(roles == {"preflight", "plan", "dispatch", "run", "verify", "export"} and sorted(exported) == sorted(export_hashes) and verified_runs == set(runs), "native stage/export stream coverage incomplete")
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
            require(value["run"] != ledger["rootRun"] and value["plan"].get("followupOf", {}).get("kind") == "security-variant-analysis"
                    and followup.get("parentPlanDigest") == runs[ledger["rootRun"]]["plan"]["nativePlan"]["digest"] and seeds,
                    "variant lacks genuine confirmed-parent followup")
            parent_packet = next((item for parent_run, item in packets.values() if parent_run["run"] == ledger["rootRun"] and item["packet"]["providerId"] == "legacy.security.adjudication"), None)
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
                "recordSha256": entry["record"]["sha256"], "sourceClosureDigest": entry["sourceClosure"]["digest"], "exportSha256": export_hashes,
                "ledgerDigest": digest(encoded(ledger)), "caseReadbackDigest": digest(encoded(record["cases"])),
                "allRequestedCoverageComplete": True, "authenticatedOutputsComplete": True, "independentVerificationComplete": True,
                "accountingComplete": True, "originalInventoryComplete": True, "stagedAdjudicationComplete": True,
                "globalQualificationOnlyExit2": any(command["exitCode"] == 2 for command in capture["commands"]), "productionQualification": False, "wholeProviderQualification": False}
    require(verified == expected, "missing source-owned maintainer observation/readback; local MACs do not authenticate provenance")
    return retained
