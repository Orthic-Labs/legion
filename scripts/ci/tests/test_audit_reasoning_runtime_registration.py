"""Checker units; synthetic values never establish runtime provenance."""
from pathlib import Path
import hashlib
import json
import runpy
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-reasoning-runtime-registration.py"))


class ReasoningRegistrationBoundaryTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
