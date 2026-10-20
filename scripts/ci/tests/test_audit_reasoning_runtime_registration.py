"""Checker units; synthetic values never establish runtime provenance."""
from pathlib import Path, PurePosixPath, PureWindowsPath
import errno
import hashlib
import json
import runpy
import unittest
import shutil
import tempfile
import stat
import subprocess
import sys

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-reasoning-runtime-registration.py"))


class ThreeMemberCapture:
    """Complete synthetic validator control; never a native provenance receipt.

    Retains every original-byte reference & exercises validate() without mocking
    its packet, accounting, staged, variant, command or provenance checks.
    """
    def __init__(self, root):
        # Match runner canonicalization before freezing any absolute binding.
        # macOS tempfile paths can alias /private/var through /var.
        root = Path(root).resolve()
        self.root = root
        self.corpus = root / API["FIXTURES"]
        # Retained native identities belong to macOS, independently of local IO.
        self.native_corpus = PurePosixPath("/Volumes/native-checkout") / API["FIXTURES"]
        self.native_capture = PurePosixPath("/Volumes/native-capture")
        shutil.copytree(Path(__file__).resolve().parents[1] / "fixtures/audit-reasoning-runtime-accuracy", self.corpus)
        self.controls = json.loads((self.corpus / "cases.json").read_text())
        self.exports = {}
        self.calls = []
        self.record_cases = {}
        self.confirmed = None
        self.capture = {"schema": API["CAPTURE_SCHEMA"],
            "host": {"platform": "macos", "runtime": "claude-code", "sessionId": "synthetic-validator-control"},
            "binary": {"sha256": "sha256:" + "1" * 64, "sourceCommit": "2" * 40,
                       "artifactId": 1, "runId": 2, "runAttempt": 1, "jobId": 3, "repository": "Orthic-Labs/legion"},
            "commands": [], "exports": [], "members": [],
            "cases": self.source_ref("cases.json"), "packetPlan": self.source_ref("packet-plan.json")}
        self.command("preflight", None, str(self.native_capture),
                     ["audit", "check-reasoning-fixtures", "--root", str(self.native_corpus)], {})
        for index, group in enumerate(API["MEMBER_PROVIDERS"]):
            member_id = f"run-{index + 1:02d}"
            base = self.native_capture / member_id
            member = {"memberId": member_id, "memberIndex": index, "providerIds": list(group),
                      "caseIds": API["member_case_ids"](self.controls, group),
                      "sourceRoot": str(base / "fixture-source"), "run": str(base / "native-run"),
                      "sourceFiles": API["expected_member_sources"](root, self.controls, group)}
            member["manifest"] = self.retain(member_id + "/manifest.json", {"schema": API["MEMBER_SCHEMA"],
                **{key: member[key] for key in ("memberId", "memberIndex", "providerIds", "caseIds", "sourceRoot", "sourceFiles")},
                "corpusRoot": str(self.native_corpus), "casesDigest": self.capture["cases"]["sha256"]})
            self.capture["members"].append(member)
            self.plan_command(member, "plan-preflight", str(base / "preflight-run"), 44)
            preflight = self.preflight(member, str(base / "preflight-run"), 44, len(group) - (index == 0))
            member["preflight"] = self.command("dispatch-preflight", member, preflight["run"],
                ["audit", "check-reasoning-dispatch", "--run", preflight["run"]], preflight)
        cumulative_admissions = cumulative_calls = cumulative_reserved = cumulative_actual = 0
        previous = None
        for member in self.capture["members"]:
            group = member["providerIds"]
            remaining = 44 - cumulative_admissions
            root_providers = [provider for provider in group if provider != "legacy.security.variant-analysis"]
            value = self.make_export(member, member["run"], root_providers, remaining)
            member_values = [value]
            if member["memberIndex"] == 0:
                member_values.append(self.make_export(member, member["run"] + "/followup",
                    ["legacy.security.variant-analysis"], remaining, value))
            member_calls = [call for exported in member_values for call in exported["authenticatedCalls"]]
            dispatch = self.dispatch(root_providers, remaining)
            raw_dispatch = self.artifact(value, "lens-dispatch.json", dispatch)
            reservations = {call["authorization"]["reservationId"]: {"callId": call["callId"], "retry": False,
                "reservedTokens": 150000, "outputTokenLimit": 2500, "transportAuthorized": True,
                "usage": call["observation"]["usage"], "nativeCostRequired": True,
                "reportedApiCostUsd": call["observation"]["reportedApiEquivalentCostUsd"]} for call in member_calls}
            self.artifact(value, "next-state.json", {"dispatchDigest": raw_dispatch["sha256"].removeprefix("sha256:"),
                "reservations": reservations, "issuances": len(reservations), "spent": {"judgment": len(reservations) * 150000},
                "budgetBlocked": [], "terminalStatus": None, "contextLimited": [], "leases": {"seat-1": {"attempts": 1}}})
            self.plan_command(member, "plan", member["run"], remaining)
            actual = self.preflight(member, member["run"], remaining, len(root_providers))
            dispatch_ref = self.command("dispatch", member, member["run"],
                ["audit", "check-reasoning-dispatch", "--run", member["run"]], actual)
            member["authorization"] = self.retain(member["memberId"] + "/authorization.json", {
                "schema": API["AUTHORIZATION_SCHEMA"], "memberId": member["memberId"], "manifest": member["manifest"],
                "remainingAdmissions": remaining, "tokenCeiling": remaining * 150000,
                "previousCheckpoint": previous, "dispatchPreflight": dispatch_ref})
            self.command("run", member, member["run"], ["audit", "run-reasoning", "--run", member["run"],
                "--strict-no-retry", "--max-calls-per-packet", "1"], {"complete": True, "status": "done"}, 2)
            refs = []
            for exported in member_values:
                run = exported["run"]
                self.command("verify", member, run, ["verify", run, "--json"], {"valid": True,
                    "runtimeCalls": {"status": "verified", "accountingRoot": member["run"]}})
                refs.append(self.command("export", member, run, ["audit", "export-reasoning", "--run", run], exported))
                self.exports[run] = exported
            self.capture["exports"].extend(refs)
            admissions = len(reservations)
            actual_usage = sum(call["observation"]["usage"]["inputTokens"] + call["observation"]["usage"]["outputTokens"] for call in member_calls)
            cumulative_admissions += admissions
            cumulative_calls += len(member_calls)
            cumulative_reserved += admissions * 150000
            cumulative_actual += actual_usage
            self.calls.extend(call["callId"] for call in member_calls)
            member["checkpoint"] = previous = self.retain(member["memberId"] + "/checkpoint.json", {
                "schema": API["CHECKPOINT_SCHEMA"], "memberId": member["memberId"], "authorization": member["authorization"],
                "remainingBefore": remaining, "admissionUnits": admissions, "physicalCalls": len(member_calls),
                "reservedTokens": admissions * 150000, "actualUsageTokens": actual_usage,
                "earmarkedTokens": admissions * 150000, "remainingAfter": 44 - cumulative_admissions,
                "cumulativeAdmissions": cumulative_admissions, "cumulativePhysicalCalls": cumulative_calls,
                "cumulativeReservedTokens": cumulative_reserved, "cumulativeActualUsageTokens": cumulative_actual,
                "cumulativeEarmarkedTokens": cumulative_admissions * 150000,
                "callIds": sorted(call["callId"] for call in member_calls), "exports": refs})
        self.capture["ledger"] = {"kind": "runner-owned-cumulative-admissions", "maxPhysicalAdmissions": 44,
            "perCallReservationTokens": 150000, "reservationCeilingTokens": 6600000, "width": 1, "retries": 0, "reclaims": 0,
            "callIds": sorted(self.calls), "admissionUnits": cumulative_admissions, "physicalCalls": cumulative_calls,
            "reservedTokens": cumulative_reserved, "actualUsageTokens": cumulative_actual,
            "earmarkedTokens": cumulative_admissions * 150000}

    def source_ref(self, name):
        path = self.corpus / name
        return {"path": path.relative_to(self.root).as_posix(), "sha256": API["digest"](path.read_bytes())}

    def retain(self, name, value, category="evidence"):
        path = self.root / "qualification/provider-accuracy" / category / name
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = API["encoded"](value)
        path.write_bytes(raw)
        return {"path": path.relative_to(self.root).as_posix(), "sha256": API["digest"](raw)}

    def command(self, role, member, run, args, value, exit_code=0):
        name = f"commands/{len(self.capture['commands']):02d}-{role}"
        stdout = self.retain(name + ".json", value)
        self.capture["commands"].append({"role": role, "memberId": member["memberId"] if member else None,
            "argv": ["/Volumes/native-binary/legion"] + args, "cwd": str(self.native_corpus),
            "environmentNames": ["CLAUDECODE", "CLAUDE_CODE_SESSION_ID"], "exitCode": exit_code,
            "stdout": stdout, "stderr": self.retain(name + ".stderr.json", {}), "run": run})
        return stdout

    def plan_command(self, member, role, run, quota):
        args = ["audit", member["sourceRoot"], "--json", "--coverage", "exhaustive", "--seat-token-budget", "150000",
                "--run-token-budget", str(quota * 150000), "--max-total-seats", str(quota), "--max-lens-seats", "1", "--out", run]
        for provider in member["providerIds"] + ["security.misuse-resistance"]:
            args.extend(["--only", provider])
        self.command(role, member, run, args, {}, 2)

    def dispatch(self, providers, quota):
        return {"seats": [{"packets": [provider + ".json" for provider in providers]}], "requiredSeats": 1,
            "reasoningBudget": {"schemaVersion": 2, "totalTokens": quota * 150000,
                                "perCallTokens": 150000, "outputTokens": 2500, "maxSeats": quota},
            "limits": {"waveWidth": 1}, "withinLimits": True, "boundedAudit": False, "coverageMode": "exhaustive"}

    def preflight(self, member, run, quota, logical_count):
        providers = [provider for provider in member["providerIds"] if provider != "legacy.security.variant-analysis"]
        dispatch = self.dispatch(providers, quota)
        count = len(member["providerIds"])
        return {"schema": "legion-reasoning-runtime-dispatch-preflight/1", "run": run,
            "memberId": member["memberId"], "memberIndex": member["memberIndex"], "caseIds": member["caseIds"],
            "providerIds": member["providerIds"], "productionDispatchValidated": True, "modelCalls": 0, "qualification": False,
            "remainingAdmissions": quota, "expectedPlantedPositives": count, "knownAnswerExpectedPositives": count,
            "expectedPairedCleanControls": count, "expectedVerifierItems": count, "verifierItemCap": 8,
            "zeroFindingReviewHeadroom": 8 - count, "logicalPendingRequestCount": logical_count,
            "plannedFreshBatchVerifierAdmissions": 1, "plannedAuthorSeats": 1, "planDigest": API["digest"](member["run"].encode()),
            "dispatch": dispatch, "dispatchDigest": API["digest"](API["encoded"](dispatch))}

    def artifact(self, value, name, content):
        # Deliberately pretty: next-state hashes original bytes, preflight hashes canonical JSON.
        raw = json.dumps(content, indent=2, ensure_ascii=False).encode()
        artifact = {"path": name, "sha256": API["digest"](raw), "bytes": len(raw), "utf8": raw.decode()}
        value["artifacts"].append(artifact)
        return artifact

    def make_export(self, member, run, providers, quota, parent=None):
        plan_digest = API["digest"](run.encode())
        plan = {"seal": {"digest": plan_digest}, "nativePlan": {"digest": plan_digest},
                "reviewContext": {"sourceRepository": member["sourceRoot"]}}
        value = {"schema": "legion-reasoning-runtime-export/1", "run": run, "plan": plan, "runtime": {},
            "authenticatedCalls": [], "packets": [], "ingested": providers, "pending": [],
            "report": {"claims": {"planDigest": plan_digest}}, "execution": {"planDigest": plan_digest, "results": []},
            "artifacts": [], "rawNativeStdoutRetained": False, "qualification": False,
            "productionQualification": False, "wholeProviderQualification": False}
        actors = []
        for index in range(2):
            identity = run + f"/call-{index}"
            observation = {"processCreated": True, "processId": 100 + len(self.exports) * 10 + (2 if parent else 0) + index,
                "contextId": identity, "responseDigest": API["digest"](identity.encode()), "sent": True,
                "rawUsage": {"input_tokens": 10, "output_tokens": 2},
                "usage": {"inputTokens": 10, "outputTokens": 2, "cachedInputTokens": 1, "retryTokens": 0, "failed": False},
                "physicalRequestDigest": API["digest"](identity.encode()), "reportedApiEquivalentCostUsd": "0.1234567890123456789"}
            call = {"kind": "legion-runtime-call", "callId": identity, "strictNoRetry": True,
                "execution": {"host": "claude-code"}, "requestDigest": observation["physicalRequestDigest"],
                "authorization": {"authorized": True, "reservationId": identity}, "observation": observation}
            value["authenticatedCalls"].append(call)
            self.artifact(value, f"runtime-calls/call-{index}.json", {**call, "authentication": {"synthetic": True}})
            actors.append({key: observation[key] for key in ("processCreated", "processId", "contextId", "responseDigest")})
        for provider in providers:
            request_id = run + "/" + provider
            cases = [case for case in self.controls["cases"] if case["providerIds"] == [provider]]
            excerpts, paths, findings = [], [], []
            for case in cases:
                fixture = self.corpus / case["fixtureRoot"]
                for path in sorted(fixture.rglob("*")):
                    if path.is_file():
                        relative = path.relative_to(self.corpus / "fixtures").as_posix()
                        paths.append(relative)
                        excerpts.append({"path": relative, "mode": "raw", "startLine": 1, "content": path.read_text()})
                for anchor in case["expected"].get("positive", []):
                    full_anchor = {**anchor, "path": case["fixtureRoot"].removeprefix("fixtures/") + "/" + anchor["path"]}
                    finding_id = f"{provider}-finding-{len(findings)}"
                    if provider == "legacy.security.adjudication":
                        finding_id = "adjudicated:candidate-1" if not findings else finding_id
                    author_finding = {"id": finding_id, "anchor": full_anchor}
                    findings.append({"findingId": finding_id, "authorFinding": author_finding, "verdict": "upheld",
                        "findingDigest": API["digest"](API["encoded"](author_finding)), "author": actors[0], "reviewer": actors[1]})
                self.record_cases[case["caseId"]] = {"caseId": case["caseId"], "requestId": request_id, "run": run,
                    "matched": True, "observedFindingIds": [row["findingId"] for row in findings
                        if row["authorFinding"]["anchor"]["path"].startswith(case["fixtureRoot"].removeprefix("fixtures/") + "/")]}
            packet = {"excerpts": excerpts}
            details = {}
            if provider == "legacy.security.adjudication":
                first = findings[0]["authorFinding"]["anchor"]
                packet["scannerCandidates"] = [{"findingId": "candidate-1", "provider": "security.misuse-resistance",
                                                  "path": first["path"], "line": first["line"]}]
                value["execution"]["results"].append({"provider": "security.misuse-resistance", "result": {"findings": [{"id": "candidate-1"}]}})
                details = self.staged(value, request_id, packet, findings, actors, first)
            if provider == "legacy.security.variant-analysis":
                confirmed = self.confirmed
                confirmed_digest = API["digest"](API["encoded"](confirmed))
                plan["followupOf"] = {"kind": "security-variant-analysis", "confirmedDigest": confirmed_digest}
                packet.update({"followup": {"parentPlanDigest": parent["plan"]["nativePlan"]["digest"], "confirmedDigest": confirmed_digest},
                    "variantSeeds": [{**confirmed[0], "parentFindingId": "adjudicated:" + confirmed[0]["candidateId"]}],
                    "variantScope": {"rootCauseSearch": {"status": "examined-frozen-source-files"},
                                     "paths": [{"relations": ["sibling-of:confirmed-parent"]}]}})
            request = {"requestId": request_id, "providerId": provider, "planDigest": plan_digest,
                       "denominatorDigest": API["digest"](API["encoded"](paths)), "denominatorPaths": paths, "packet": packet}
            work = {"providerId": provider, "request": request}
            self.artifact(value, "lens-packets/" + provider + ".json", work)
            proof = {"requestId": request_id, "packetDigest": API["digest"](API["encoded"](packet)),
                     "complete": True, "truncated": False, "source": "host-transport"}
            verification = {**proof, "findings": findings}
            self.artifact(value, "runtime-delivery/" + provider + ".json", {"message": {"evidence": proof}})
            self.artifact(value, "runtime-verification/" + provider + ".json", {"message": {"evidence": verification}})
            evidence = {"delivery": proof, "verification": verification}
            if provider == "legacy.security.adjudication":
                evidence["adjudication"] = details["adjudicationDeliveryEvidence"]
            bare = {"complete": True, "coverageGaps": [], "details": details}
            accepted = {**bare, "details": {**details, "executionReceipt": {"requestId": request_id, "complete": True,
                "gaps": [], "providerId": provider, "planDigest": plan_digest,
                "denominatorDigest": request["denominatorDigest"], "resultDigest": API["digest"](API["encoded"](bare))}}}
            self.artifact(value, "lens-receipts/" + provider + ".json", {"result": accepted})
            value["packets"].append({"packet": work, "authenticatedEvidence": evidence})
            value["execution"]["results"].append({"provider": provider, "skipped": False, "result": accepted})
        return value

    def staged(self, value, request_id, packet, findings, actors, anchor):
        final = {"candidateId": "candidate-1", "candidateProvider": "security.misuse-resistance",
            "adjudicatorProvider": "legacy.security.adjudication", "domain": "security", "verdict": "TRUE_POSITIVE", "verdictDigest": ""}
        final["verdictDigest"] = API["digest"](API["encoded"](final))
        self.confirmed = [{"candidateId": "candidate-1", "path": anchor["path"], "line": anchor["line"],
                           "verdict": "TRUE_POSITIVE", "severity": "high", "verdictDigest": final["verdictDigest"]}]
        submitted, observations = [], []
        for index, stage in enumerate(("batch", "confirmation")):
            verdict = {"candidateId": "candidate-1", "stage": stage, "workItemId": stage}
            submitted.append(verdict)
            stage_packet = {"kind": "legion-audit-adjudication-seat", "itemId": stage, "stage": stage, "packet": {"candidate": "candidate-1"}}
            observation = {**actors[index], "kind": "legion-adjudication-stage-observation", "complete": True, "truncated": False,
                "observedContextId": actors[index]["contextId"], "workItemId": stage, "stage": stage,
                "workPacketDigest": API["digest"](API["encoded"](stage_packet["packet"])),
                "deliveredPacketBytes": len(API["encoded"](stage_packet["packet"])), "candidateIds": ["candidate-1"],
                "verdictDigests": {"candidate-1": API["digest"](API["encoded"](verdict))},
                "sourceDelivery": [{"candidateId": "candidate-1", "path": anchor["path"], "startLine": anchor["line"]}]}
            observations.append(observation)
            self.artifact(value, f"adjudication/packets/{stage}.json", stage_packet)
            self.artifact(value, f"adjudication/results/{stage}.json", {"verdicts": [verdict]})
            self.artifact(value, f"runtime-adjudication/{stage}.json", {"message": {"kind": "legion-audit-runtime-adjudication",
                "requestId": request_id, "packetDigest": API["digest"](API["encoded"](packet)),
                "evidence": {"observation": observation, "stagePacket": stage_packet}}})
        return {"adjudicationLedger": {"ledger": {"complete": True, "outstanding": [], "contested": [], "voidedBatches": [],
            **{key: {"expected": 1, "ingested": 1} for key in ("batches", "confirmations", "spotChecks", "individualReviews")}}},
            "rawAdjudicationVerdicts": submitted, "adjudicationDeliveryEvidence": observations,
            "securityVerdicts": [final], "securityConfirmed": self.confirmed,
            "lensFindings": [row["authorFinding"] for row in findings]}

    def entry(self, provider):
        # Rebind retained chain after a negative control changes an upstream
        # stream, so its intended native boundary decides instead of stale refs.
        previous = None
        for member in self.capture["members"]:
            authorization = json.loads(API["reference"](self.root, member["authorization"]).read_text())
            authorization["previousCheckpoint"] = previous
            member["authorization"] = self.retain(member["memberId"] + "/authorization.json", authorization)
            checkpoint = json.loads(API["reference"](self.root, member["checkpoint"]).read_text())
            checkpoint["authorization"] = member["authorization"]
            checkpoint["exports"] = [command["stdout"] for command in self.capture["commands"]
                if command["memberId"] == member["memberId"] and command["role"] == "export"]
            member["checkpoint"] = previous = self.retain(member["memberId"] + "/checkpoint.json", checkpoint)
        capture_ref = self.retain("capture.json", self.capture)
        closure = "sha256:" + "3" * 64
        retrieval = {"schema": "legion-reasoning-binary-retrieval-verification/1",
            "method": "authenticated-github-artifact-retrieval", "verified": True, "binary": self.capture["binary"],
            "sourceClosureDigest": closure, "artifactArchive": self.retain("archive.json", {}),
            "jobLog": self.retain("job-log.json", {}), "noCall": {"verified": True,
                "sourceCommit": self.capture["binary"]["sourceCommit"], "binarySha256": self.capture["binary"]["sha256"],
                "log": self.retain("no-call-log.json", {})}}
        retrieval_ref = self.retain("retrieval.json", retrieval, "verification")
        cases = [self.record_cases[case["caseId"]] for case in self.controls["cases"] if case["providerIds"] == [provider]]
        record = {"schema": "legion-reasoning-runtime-accuracy/1", "provider": provider, "family": API["FAMILY"],
            "stage": "finding", "scope": API["SCOPE"], "qualificationEligible": True, "productionQualification": False,
            "wholeProviderQualification": False, "auditCleanClaim": False, "cases": cases,
            "qualificationDigest": API["digest"](API["encoded"](cases))}
        record_ref = self.retain(provider + ".json", record, "records")
        verification = {"schema": "legion-reasoning-native-host-provenance-verification/1",
            "method": "maintainer-observed-native-host-capture-and-authenticated-binary-retrieval", "verified": True,
            "captureSha256": capture_ref["sha256"], "binaryRetrievalVerificationSha256": retrieval_ref["sha256"],
            "recordSha256": record_ref["sha256"], "sourceClosureDigest": closure,
            "exportSha256": [ref["sha256"] for ref in self.capture["exports"]],
            "ledgerDigest": API["digest"](API["encoded"](self.capture["ledger"])), "caseReadbackDigest": API["digest"](API["encoded"](cases)),
            **{key: True for key in ("allRequestedCoverageComplete", "authenticatedOutputsComplete", "independentVerificationComplete",
                "accountingComplete", "originalInventoryComplete", "stagedAdjudicationComplete", "globalQualificationOnlyExit2")},
            "productionQualification": False, "wholeProviderQualification": False}
        entry = {"provider": provider, "family": API["FAMILY"], "stage": "finding", "scope": API["SCOPE"],
            "record": record_ref, "sourceClosure": {"digest": closure},
            "provenance": {"capture": capture_ref, "binaryRetrievalVerification": retrieval_ref},
            "provenanceVerification": self.retain(provider + "-verification.json", verification, "verification")}
        return entry, record


class ReasoningRegistrationBoundaryTests(unittest.TestCase):
    def test_complete_three_member_capture_validates_all_seventeen_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            # Force a noncanonical caller spelling on every host, rather than
            # relying on CI's macOS /var -> /private/var tempfile alias.
            detour = Path(temporary) / "detour"
            detour.mkdir()
            caller_root = detour / ".." / "capture-root"
            fixture = ThreeMemberCapture(caller_root)
            self.assertNotEqual(str(caller_root), str(fixture.root))
            self.assertEqual(fixture.root, caller_root.resolve())
            self.assertEqual(len(fixture.record_cases), 34)
            self.assertEqual(len(fixture.capture["exports"]), 4)  # Three roots + retained variant child shape.
            for provider in sorted(API["PROVIDERS"]):
                with self.subTest(provider=provider):
                    entry, record = fixture.entry(provider)
                    retained = API["validate"](fixture.root, entry, record)
                    self.assertIn(entry["provenanceVerification"]["path"], retained)

    def test_symlink_root_capture_validates_all_seventeen_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary).resolve() / "real-root"
            target.mkdir()
            alias = target.parent / "root-alias"
            try:
                alias.symlink_to(target, target_is_directory=True)
            except NotImplementedError as error:
                self.skipTest(f"directory symlinks unsupported: {error}")
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EPERM, errno.ENOSYS, errno.ENOTSUP} and getattr(error, "winerror", None) != 1314:
                    raise
                self.skipTest(f"directory symlink unavailable: {error}")
            fixture = ThreeMemberCapture(alias)
            self.assertEqual(fixture.root, target)
            self.assertNotEqual(str(alias), str(fixture.root))
            for provider in sorted(API["PROVIDERS"]):
                with self.subTest(provider=provider):
                    entry, record = fixture.entry(provider)
                    retained = API["validate"](fixture.root, entry, record)
                    self.assertIn(entry["provenanceVerification"]["path"], retained)

    def test_native_posix_identity_does_not_follow_verifier_windows_rules(self):
        run = "/Volumes/native-capture/run-01/native-run"
        self.assertFalse(PureWindowsPath(run).is_absolute())
        native = API["safe_absolute"](run)
        self.assertIsInstance(native, PurePosixPath)
        self.assertEqual(str(native / "followup"), run + "/followup")
        self.assertEqual(str(native.parent / "preflight-run"), "/Volumes/native-capture/run-01/preflight-run")
        for invalid in (r"C:\native\run", r"\\server\run", "/native\\run", "relative/run",
                        "/native/../run", "/native//run", "/native/./run", "//native/run", "/native/run/", "/native/\0run"):
            with self.subTest(path=invalid), self.assertRaises(AssertionError):
                API["safe_absolute"](invalid)

    def test_complete_native_capture_is_independent_of_local_checkout_location(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = ThreeMemberCapture(Path(temporary) / "local-checkout-one")
            second = ThreeMemberCapture(Path(temporary) / "different-checkout-two")
            self.assertNotEqual(first.root, second.root)
            self.assertEqual(first.capture, second.capture)
            for fixture in (first, second):
                for provider in sorted(API["PROVIDERS"]):
                    with self.subTest(checkout=fixture.root.name, provider=provider):
                        entry, record = fixture.entry(provider)
                        API["validate"](fixture.root, entry, record)

    def test_full_capture_rejects_native_location_and_local_source_drift(self):
        for mutation, message in (("manifest", "corpus roots differ"), ("cwd", "command identity"),
                                  ("preflight-root", "corpus preflight selector"),
                                  ("source-bytes", "source subset/hash"), ("cases-bytes", "corpus source binding")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = ThreeMemberCapture(Path(temporary))
                if mutation == "manifest":
                    member = fixture.capture["members"][1]
                    manifest = json.loads(API["reference"](fixture.root, member["manifest"]).read_text())
                    manifest["corpusRoot"] = "/Volumes/foreign-corpus"
                    member["manifest"] = fixture.retain("foreign-corpus-manifest.json", manifest)
                elif mutation == "cwd":
                    fixture.capture["commands"][0]["cwd"] = "/Volumes/foreign-corpus"
                elif mutation == "preflight-root":
                    fixture.capture["commands"][0]["argv"][-1] = "/Volumes/foreign-corpus"
                elif mutation == "source-bytes":
                    relative = next(iter(fixture.capture["members"][0]["sourceFiles"]))
                    path = fixture.corpus / "fixtures" / relative
                    path.write_bytes(path.read_bytes() + b"\nchanged local source\n")
                else:
                    path = fixture.corpus / "cases.json"
                    path.write_bytes(path.read_bytes() + b"\n")
                entry, record = fixture.entry("reasoning.security")
                with self.assertRaisesRegex(AssertionError, message):
                    API["validate"](fixture.root, entry, record)

    def test_full_capture_rejects_disconnected_preflight_and_usage_ceiling(self):
        for mutation, message in (("dispatch", "dispatch preflight"), ("plan", "plan/logical"),
                                  ("cost", "usage/reservation"), ("usage", "usage/reservation"),
                                  ("quota", "quota/coverage"), ("followup", "frozen member")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = ThreeMemberCapture(Path(temporary))
                member = fixture.capture["members"][0]
                command = next(row for row in fixture.capture["commands"] if row["memberId"] == member["memberId"] and row["role"] == "dispatch")
                if mutation in {"dispatch", "plan"}:
                    value = json.loads(API["reference"](fixture.root, command["stdout"]).read_text())
                    value["dispatchDigest" if mutation == "dispatch" else "planDigest"] = "sha256:" + "0" * 64
                    command["stdout"] = fixture.retain("mutated-dispatch.json", value)
                    auth = json.loads(API["reference"](fixture.root, member["authorization"]).read_text())
                    auth["dispatchPreflight"] = command["stdout"]
                    member["authorization"] = fixture.retain("mutated-authorization.json", auth)
                elif mutation == "quota":
                    plan = next(row for row in fixture.capture["commands"] if row["memberId"] == member["memberId"] and row["role"] == "plan")
                    plan["argv"][plan["argv"].index("--run-token-budget") + 1] = "6600001"
                else:
                    exported = fixture.exports[member["run"]]
                    if mutation == "followup":
                        # Export itself remains internally valid; ownership cannot use substring matching.
                        child = fixture.exports[member["run"] + "/followup"]
                        child["run"] = member["run"] + "/followup-forged"
                        exported = child
                    else:
                        state_artifact = next(item for item in exported["artifacts"] if item["path"] == "next-state.json")
                        state = json.loads(state_artifact["utf8"])
                        reservation = next(iter(state["reservations"].values()))
                        if mutation == "cost":
                            reservation["reportedApiCostUsd"] = "0.9"
                        else:
                            reservation["usage"]["inputTokens"] = 150001
                            # Keep original call & authenticated artifact consistent so ceiling check decides.
                            call = next(row for row in exported["authenticatedCalls"] if row["callId"] == reservation["callId"])
                            call["observation"]["usage"] = reservation["usage"]
                            original = next(item for item in exported["artifacts"] if item["path"] == "runtime-calls/call-0.json")
                            original_row = json.loads(original["utf8"])
                            original_row["observation"]["usage"] = reservation["usage"]
                            exported["artifacts"].remove(original)
                            fixture.artifact(exported, original["path"], original_row)
                        exported["artifacts"].remove(state_artifact)
                        fixture.artifact(exported, "next-state.json", state)
                    export_command = next(row for row in fixture.capture["commands"] if row["role"] == "export"
                        and row["run"] == (member["run"] + "/followup" if mutation == "followup" else member["run"]))
                    old_ref = export_command["stdout"]
                    new_ref = fixture.retain("mutated-export.json", exported)
                    export_command["stdout"] = new_ref
                    fixture.capture["exports"] = [new_ref if ref == old_ref else ref for ref in fixture.capture["exports"]]
                entry, record = fixture.entry("reasoning.security")
                with self.assertRaisesRegex(AssertionError, message):
                    API["validate"](fixture.root, entry, record)

    def test_isolated_source_must_match_native_plan_and_fresh_capture_root(self):
        source = "/scratch/capture/fixture-source"
        run = "/scratch/capture/native-run"
        API["isolated_source_evidence"](source, run, {"reviewContext": {"sourceRepository": source}})
        for incorrect_source, incorrect_plan in (
                ("/source/corpus/fixtures", {"reviewContext": {"sourceRepository": "/source/corpus/fixtures"}}),
                (source, {"reviewContext": {"sourceRepository": "/unrelated"}}),
                (source, {})):
            with self.assertRaises(AssertionError):
                API["isolated_source_evidence"](incorrect_source, run, incorrect_plan)

    def test_budget_state_binds_exact_pretty_dispatch_bytes_not_canonical_json(self):
        # Native next-state stores SHA-256 of original file bytes as bare hex.
        raw = '{\n  "seats": [{"packets": ["correctness.json"]}],\n  "requiredSeats": 1\n}'
        stored_hash = hashlib.sha256(raw.encode()).hexdigest()
        canonical_hash = hashlib.sha256(json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertNotEqual(stored_hash, canonical_hash)
        artifact = {"path": "lens-dispatch.json", "utf8": raw, "sha256": "sha256:" + stored_hash}
        API["dispatch_state_evidence"]({"dispatchDigest": stored_hash}, artifact)
        for incorrect in (canonical_hash, "sha256:" + canonical_hash, "sha256:" + stored_hash):
            with self.assertRaises(AssertionError):
                API["dispatch_state_evidence"]({"dispatchDigest": incorrect}, artifact)

    def test_actual_production_author_packets_capped_at_eight(self):
        # Multiple logical lenses may share one physical author request.
        seats = [{"packets": ["correctness.json", "architecture.json", "security.json"]} for _ in range(8)]
        API["production_packet_bound"]({"seats": seats, "requiredSeats": 8})
        for dispatch in ({"seats": seats + [{}], "requiredSeats": 9},
                         {"seats": seats + [{}], "requiredSeats": 8},
                         {"seats": seats, "requiredSeats": 7},
                         {"seats": seats, "requiredSeats": 8.0},
                         {"seats": [{}], "requiredSeats": True},
                         {"seats": [], "requiredSeats": 0}, {}):
            with self.assertRaises(AssertionError):
                API["production_packet_bound"](dispatch)

    def test_dispatch_preflight_binds_actual_retained_production_packets(self):
        dispatch = {"seats": [{"packets": ["correctness.json"]}], "requiredSeats": 1}
        preflight = {"dispatch": dispatch, "dispatchDigest": API["digest"](API["encoded"](dispatch))}
        API["dispatch_preflight_evidence"](preflight, dispatch)
        for changed in ({"dispatch": {}, "dispatchDigest": preflight["dispatchDigest"]},
                        {"dispatch": dispatch, "dispatchDigest": "sha256:forged"}):
            with self.assertRaises(AssertionError):
                API["dispatch_preflight_evidence"](changed, dispatch)
        oversized = {"seats": [{} for _ in range(9)], "requiredSeats": 9}
        with self.assertRaises(AssertionError):
            API["dispatch_preflight_evidence"](preflight, oversized)

    def test_exact_seventeen_provider_boundary(self):
        self.assertEqual(len(API["PROVIDERS"]), 17)
        for provider in ("reasoning.unknown", "security.misuse-resistance", "code.rust"):
            with self.assertRaises(AssertionError):
                API["adapter"]({"provider": provider, "family": "reasoning-runtime", "stage": "finding", "scope": "known-answer-fixture-cases"})

    def test_three_frozen_members_partition_all_paired_controls(self):
        controls = json.loads((Path(__file__).resolve().parents[1] / "fixtures/audit-reasoning-runtime-accuracy/cases.json").read_text())
        groups = API["MEMBER_PROVIDERS"]
        self.assertEqual([len(group) for group in groups], [6, 6, 5])
        self.assertEqual(set().union(*(set(group) for group in groups)), API["PROVIDERS"])
        self.assertEqual(sum(len(API["member_case_ids"](controls, group)) for group in groups), 34)
        self.assertEqual(len({case_id for group in groups for case_id in API["member_case_ids"](controls, group)}), 34)
        self.assertEqual(API["PER_CALL_TOKENS"], 150000)
        self.assertEqual(API["MAX_RESERVED_TOKENS"], 6600000)

    def test_member_manifest_binds_exact_source_subset_and_quota_chain(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / API["FIXTURES"]
            providers = list(API["MEMBER_PROVIDERS"][0])
            cases = []
            for provider in providers:
                slug = provider.replace(".", "-")
                for polarity in ("planted", "clean"):
                    case_id = f"{slug}-{polarity}"
                    relative = f"fixtures/{slug}-{polarity}/source.txt"
                    path = fixture_root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(case_id + "\n")
                    cases.append({"caseId": case_id, "providerIds": [provider], "fixtureRoot": f"fixtures/{slug}-{polarity}"})
            fixture_root.joinpath("cases.json").write_text(json.dumps({"schema": "test", "cases": cases}))
            controls = {"cases": cases}
            source_files = API["expected_member_sources"](root, controls, providers)
            digest = API["digest"]

            def retain(name, value):
                path = root / "qualification/provider-accuracy/evidence" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                path.write_bytes(raw)
                return {"path": path.relative_to(root).as_posix(), "sha256": digest(raw)}

            manifest_ref = retain("member.json", {"schema": API["MEMBER_SCHEMA"], "memberId": "run-01", "memberIndex": 0,
                "corpusRoot": "/Volumes/native-checkout/corpus", "providerIds": providers,
                "caseIds": API["member_case_ids"](controls, providers), "sourceRoot": "/tmp/run-01/fixture-source",
                "sourceFiles": source_files, "casesDigest": digest(fixture_root.joinpath("cases.json").read_bytes())})
            dispatch_ref = retain("dispatch.json", {"modelCalls": 0})
            preflight_ref = retain("preflight.json", {"memberId": "run-01"})
            authorization_ref = retain("authorization.json", {"schema": API["AUTHORIZATION_SCHEMA"],
                "memberId": "run-01", "manifest": manifest_ref, "remainingAdmissions": 44,
                "tokenCeiling": 6600000, "previousCheckpoint": None, "dispatchPreflight": dispatch_ref})
            checkpoint_ref = retain("checkpoint.json", {"schema": API["CHECKPOINT_SCHEMA"], "memberId": "run-01",
                "authorization": authorization_ref, "remainingBefore": 44, "admissionUnits": 1, "physicalCalls": 1,
                "reservedTokens": 150000, "actualUsageTokens": 12, "earmarkedTokens": 150000,
                "remainingAfter": 43, "cumulativeAdmissions": 1, "cumulativePhysicalCalls": 1,
                "cumulativeReservedTokens": 150000, "cumulativeActualUsageTokens": 12,
                "cumulativeEarmarkedTokens": 150000, "callIds": ["call-1"], "exports": []})
            row = {"memberId": "run-01", "memberIndex": 0, "providerIds": providers,
                "caseIds": API["member_case_ids"](controls, providers), "sourceRoot": "/tmp/run-01/fixture-source",
                "run": "/tmp/run-01/native-run", "sourceFiles": source_files,
                "manifest": manifest_ref, "preflight": preflight_ref,
                "authorization": authorization_ref, "checkpoint": checkpoint_ref}

            def retained_json(ref):
                path = API["reference"](root, ref)
                return json.loads(path.read_text())

            API["validate_member"](root, controls, row, 0, None, retained_json)
            changed = {**row, "sourceFiles": {**source_files, "unassigned.txt": "sha256:" + "0" * 64}}
            with self.assertRaises(AssertionError):
                API["validate_member"](root, controls, changed, 0, None, retained_json)

    def test_legacy_capture_schema_is_not_accepted_for_registration(self):
        self.assertEqual(API["CAPTURE_SCHEMA"], "legion-reasoning-native-host-capture/2")

    def test_fixture_scope_never_expands_to_repository(self):
        with self.assertRaises(AssertionError):
            API["adapter"]({"provider": "reasoning.security", "family": "reasoning-runtime", "stage": "finding", "scope": "whole-repository"})

    def test_local_epoch_mac_is_not_export_authority(self):
        with self.assertRaises(AssertionError):
            API["export_evidence"]({"schema": "legion-reasoning-runtime-export/1", "authentication": {"alg": "HMAC-SHA256"}})

    def test_absent_actor_or_call_cannot_establish_fresh_verifier(self):
        for actor in (None, {}, {"processCreated": True, "processId": 12, "contextId": "synthetic", "responseDigest": "synthetic"}):
            with self.assertRaises(AssertionError):
                API["actor"](actor, [])

    def test_duplicate_call_binding_is_not_unique_identity(self):
        actor = {"processCreated": True, "processId": 12, "contextId": "synthetic", "responseDigest": "synthetic"}
        with self.assertRaises(AssertionError):
            API["actor"](actor, [{"observation": actor}, {"observation": actor}])

    def test_qualification_fields_deny_unbounded_claims(self):
        fields = API["qualification_fields"]()
        self.assertIs(fields["productionQualification"], False)
        self.assertIs(fields["wholeProviderQualification"], False)
        self.assertIs(fields["auditCleanClaim"], False)

    def test_staged_contract_cannot_bypass_missing_native_ledger(self):
        with self.assertRaises(AssertionError):
            API["staged_evidence"]({"packet": {}}, {}, [], {"details": {}}, {})

    def test_duplicate_json_refused(self):
        with self.assertRaises(AssertionError):
            API["parsed"]('{"verified":false,"verified":true}')

    def test_non_json_numeric_usage_refused(self):
        with self.assertRaises(AssertionError):
            API["parsed"]('{"inputTokens":NaN}')


class RetainedNoCallBinaryGuardTests(unittest.TestCase):
    """Exercise source-owned post-build guard; no native execution or provenance."""
    def run_guard(self, root):
        shell = (Path(__file__).resolve().parents[1] / "right-git-ci.sh").read_text()
        marker = "<<'REASONING_PY'\n"
        self.assertEqual(shell.count(marker), 1)
        guard = shell.split(marker, 1)[1].split("\nREASONING_PY", 1)[0]
        return subprocess.run([sys.executable, "-", str(root), "a" * 40, "macOS", "ARM64"],
                              input=guard, text=True, capture_output=True, check=False)

    def write_control(self, root):
        binary = root / "legion"
        binary.write_bytes(b"original")
        record = {"schema": "legion-reasoning-native-runner/1", "sourceRevision": "a" * 40,
                  "platform": {"os": "macOS", "architecture": "ARM64"},
                  "binary": {"path": "legion", "sha256": "sha256:" + hashlib.sha256(binary.read_bytes()).hexdigest(),
                             "bytes": binary.stat().st_size, "mode": stat.S_IMODE(binary.stat().st_mode)},
                  "modelCalls": 0, "qualification": False}
        (root / "runner.json").write_text(json.dumps(record))
        return binary, record

    def test_exact_retained_bytes_pass_post_build_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_control(root)
            result = self.run_guard(root)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_same_length_binary_mutation_fails_post_build_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, _ = self.write_control(root)
            binary.write_bytes(b"mutated!")
            result = self.run_guard(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("retained CLI differs from bytes exercised", result.stderr)

    def test_source_revision_drift_fails_post_build_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, record = self.write_control(root)
            record["sourceRevision"] = "b" * 40
            (root / "runner.json").write_text(json.dumps(record))
            result = self.run_guard(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("retained no-call runner source/platform differs", result.stderr)


if __name__ == "__main__":
    unittest.main()
