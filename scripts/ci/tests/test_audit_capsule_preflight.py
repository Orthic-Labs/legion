"""Capsule source Git setup preserves isolated fixture bytes."""

import copy
import json
import re
import subprocess
import tempfile
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-capsule-preflight.py"))


class CapsuleFixtureGitTests(unittest.TestCase):
    def test_fixture_baseline_commits_exact_source_files_without_rewriting_them(self):
        with tempfile.TemporaryDirectory(prefix="capsule-fixture-git-") as temporary:
            source = Path(temporary) / "source"
            source.mkdir()
            texts = {"src/main.rs": "fn main() {}\n", "README.md": "café\r\nsource-owned fixture\n"}
            expected = {relative: text.encode("utf-8") for relative, text in texts.items()}
            hashes = API["write_fixture_sources"](source, texts)

            API["initialize_fixture_git"](source, hashes)

            tracked = subprocess.run(["git", "-C", str(source), "ls-files", "-z"],
                                     check=True, capture_output=True).stdout.split(b"\0")
            self.assertEqual({path.decode() for path in tracked if path}, set(expected))
            self.assertTrue(subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                                           check=True, capture_output=True).stdout.strip())
            self.assertEqual({relative: (source / relative).read_bytes() for relative in expected}, expected)


class CapsulePlanResultTests(unittest.TestCase):
    def item(self):
        text = "portable directory creation\n"
        return {"providerId": "reasoning.platform-parity", "lens": "platform-parity", "capsuleId": "unit",
                "nativeContract": "audit-lens-platform-parity-v1",
                "case": {"id": "clean", "kind": "clean", "files": {"src/platform.rs": text}, "expected": [],
                         "requiredEvidence": [{"path": "src/platform.rs", "lineRange": [1, 1], "role": role}
                                              for role in ("contract", "caller", "behavior")]}}

    def write_plan(self, run, item):
        provider, lens, contract = item["providerId"], item["lens"], item["nativeContract"]
        packet = {"kind": "legion-reasoning-packet", "provider": provider, "contract": contract,
                  "lensPlan": {"lens": lens}, "binding": {"planDigest": "unit-plan"},
                  "excerptCoverage": {"omittedPaths": [], "truncatedPaths": []},
                  "excerpts": [{"path": "src/platform.rs", "startLine": 1, "endLine": 1, "mode": "raw",
                                "content": item["case"]["files"]["src/platform.rs"]}]}
        envelope = {"providerId": provider, "lensIds": [lens],
                    "request": {"providerId": provider, "contract": contract, "planDigest": "unit-plan", "packet": packet}}
        packet_path = run / "packet.json"
        packet_path.write_bytes(API["encoded"](envelope))
        seat = {"providers": [provider], "lensIds": [lens], "perCallTokenAllowance": 10000,
                "outputTokenLimit": 2000, "outputTokenCeiling": 2500, "initialPhysicalCalls": 1}
        dispatch = {"limits": API["LIMITS"], "withinLimits": True, "violations": [], "deferredWork": [],
                    "seats": [seat], "requiredSeats": 1, "requiredInitialCalls": 1, "gatherCalls": 0,
                    "followupReserveCalls": 1, "initialCallReservationTokens": 10000, "followupReserveTokens": 10000,
                    **{key: 0 for key in ("packetBytes", "modelVisibleInputBytes", "seatReadBytes",
                                           "unsharedRequestBytes", "physicalRequestBytesSaved")}}
        return {"kind": "audit-provider-plan", "auditStatus": "incomplete", "qualityGate": "unproven",
                "completionValidation": "not-run", "processExecution": "not-run", "processState": "not-run",
                "gaps": ["plan-only"], "inputGaps": [], "providers": [provider], "coverageMode": "exhaustive",
                "planDigest": "unit-plan", "lensDispatch": dispatch,
                "lensWork": [{"provider": provider, "lensIds": [lens], "deferredParts": 0,
                              "selectedParts": 1, "partsTotal": 1, "packet": str(packet_path),
                              "packetDigest": API["sha"](API["encoded"](packet))}]}

    def test_exit_two_plan_runs_full_packet_and_required_source_projection(self):
        with tempfile.TemporaryDirectory(prefix="capsule-plan-result-") as temporary:
            root = Path(temporary).resolve()

            def native_plan(command, **kwargs):
                run = Path(command[command.index("--out") + 1])
                plan = self.write_plan(run, self.item())
                raw = API["encoded"](plan)
                (run / "plan.json").write_bytes(raw)
                return SimpleNamespace(stdout=raw, stderr=b"", returncode=2)

            with patch.dict(API["run_case"].__globals__,
                            {"subprocess": SimpleNamespace(run=native_plan, TimeoutExpired=subprocess.TimeoutExpired),
                             "initialize_fixture_git": lambda *_: None}):
                result = API["run_case"](root, root / "legion", root / "out", 1, self.item())
            self.assertEqual(result["status"], "ready")
            self.assertEqual(result["returnCode"], 2)
            self.assertEqual(result["modelCalls"], 0)
            self.assertEqual(len(result["packets"]), 1)
            self.assertTrue(all(window["textRetained"] for window in result["requiredWindows"]))
            self.assertEqual(result["projectedContentCoverage"][0]["lineCoverageLowerBound"], 1)

    def test_exit_two_does_not_mask_audit_execution_or_dispatch_failures(self):
        changes = [("kind", "audit-report"), ("auditStatus", "pass"), ("qualityGate", "proven"),
                   ("completionValidation", "pass"), ("processExecution", "executed"),
                   ("processState", "complete"), ("gaps", []), ("gaps", ["plan-only", "missing-input"]),
                   ("inputGaps", ["missing-source"]), ("coverageMode", "sampled")]
        with tempfile.TemporaryDirectory(prefix="capsule-plan-result-") as temporary:
            run = Path(temporary).resolve()
            original = self.write_plan(run, self.item())
            for key, value in changes:
                with self.subTest(field=key, value=value):
                    plan = copy.deepcopy(original)
                    plan[key] = value
                    with self.assertRaises(ValueError):
                        API["inspect_plan"](plan, run, self.item(), 2)
            for code in (0, 1, 3, -9):
                with self.subTest(exit=code), self.assertRaises(ValueError):
                    API["inspect_plan"](original, run, self.item(), code)
            for key, value in (("withinLimits", False), ("deferredWork", ["packet.json"]), ("violations", ["over-budget"])):
                with self.subTest(dispatch=key):
                    plan = copy.deepcopy(original)
                    plan["lensDispatch"][key] = value
                    with self.assertRaises(ValueError):
                        API["inspect_plan"](plan, run, self.item(), 2)

    def test_clean_platform_capsule_keeps_both_applicable_target_behaviors_in_evidence(self):
        root = Path(__file__).resolve().parents[3]
        document = json.loads((root / "evals/audit-bench/capsules/conditional.json").read_bytes())
        capsule = next(row for row in document["capsules"] if row["lens"] == "platform-parity")
        case = next(row for row in capsule["cases"] if row["kind"] == "clean")
        source = case["files"]["src/platform.rs"]
        self.assertIn('#[cfg(target_os = "windows")]', source)
        self.assertIn('#[cfg(not(target_os = "windows"))]', source)
        bodies = re.findall(r'pub fn ensure_workspace\(path: &Path\) -> std::io::Result<\(\)> \{\n(.*?)\n\}', source, re.S)
        self.assertEqual(bodies, ["    std::fs::create_dir_all(path)"] * 2)
        window = next(row for row in case["requiredEvidence"] if row["role"] == "behavior")
        self.assertEqual("\n".join(source.splitlines()[window["lineRange"][0] - 1:window["lineRange"][1]]).count("create_dir_all(path)"), 2)
        self.assertEqual(case["expected"], [])


class CapsuleContractContextProjectionTests(unittest.TestCase):
    DOC = "docs/adr/0012-layer-boundaries.md"
    FILES = {DOC: "# ADR\nui must not import storage\nrationale\n",
             "src/ui.ts": "import { db } from './db';\nexport const view = db;\n"}
    EXCERPT = {"path": "src/ui.ts", "startLine": 1, "endLine": 2, "mode": "raw",
               "content": "import { db } from './db';\nexport const view = db;\n"}
    EVIDENCE = [{"path": DOC, "lineRange": [1, 2], "role": "contract"},
                {"path": "src/ui.ts", "lineRange": [1, 1], "role": "caller"},
                {"path": "src/ui.ts", "lineRange": [2, 2], "role": "behavior"}]

    def project(self, context, evidence=None, excerpts=None):
        _, windows, gaps = API["projection"](self.FILES, [], evidence or self.EVIDENCE,
                                             [self.EXCERPT] if excerpts is None else excerpts, context)
        return windows, [gap["kind"] for gap in gaps]

    def doc(self, content):
        return {"docs": [{"path": self.DOC, "content": content}], "domainContract": None}

    def test_doc_context_text_proves_contract_window_without_source_excerpt(self):
        windows, gaps = self.project(self.doc(self.FILES[self.DOC]))
        self.assertEqual(gaps, [])
        self.assertTrue(all(window["textRetained"] for window in windows))

    def test_without_context_the_contract_is_still_unproven(self):
        _, gaps = self.project(None)
        self.assertEqual(sorted(gaps), ["required-evidence-text-not-projected", "source-not-in-excerpts"])

    def test_truncated_or_altered_doc_context_does_not_prove_the_window(self):
        for content in ("# ADR\n", "# ADR\nui may import [REDACTED]\n"):
            with self.subTest(content=content):
                _, gaps = self.project(self.doc(content))
                self.assertIn("required-evidence-text-not-projected", gaps)

    def test_doc_context_never_proves_source_roles(self):
        text = self.FILES[self.DOC]
        # A non-contract role on a document needs source excerpts; context text does not count.
        evidence = [dict(row, role="behavior") if row["path"] == self.DOC else row for row in self.EVIDENCE]
        _, gaps = self.project(self.doc(text), evidence=evidence)
        self.assertIn("required-evidence-text-not-projected", gaps)
        self.assertIn("source-not-in-excerpts", gaps)
        # Source files still have to come from excerpts.
        _, gaps = self.project(self.doc(text), excerpts=[])
        self.assertIn("source-not-in-excerpts", gaps)
        self.assertIn("required-evidence-text-not-projected", gaps)

    def test_bound_domain_contract_text_proves_contract_but_absent_does_not(self):
        bound = {"docs": [], "domainContract": {"status": "bound", "evaluation": {"note": "# ADR\nui must not import storage"}}}
        _, gaps = self.project(bound)
        self.assertEqual(gaps, [])
        bound["domainContract"]["status"] = "absent"
        _, gaps = self.project(bound)
        self.assertIn("required-evidence-text-not-projected", gaps)


if __name__ == "__main__":
    unittest.main()
