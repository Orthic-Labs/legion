"""Security completion regressions; no native process execution."""
import copy
from pathlib import Path
import runpy
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-cargo-deny-accuracy.py"))


class CargoDenyCompletion(unittest.TestCase):
    def report(self, bits):
        rows, fields = [], {}
        for bit, name in enumerate(["advisories", "bans", "licenses", "sources"]):
            failed = bool(bits & (1 << bit))
            fields[name] = {"errors": int(failed), "warnings": 0, "notes": 0, "helps": 0}
            if failed:
                rows.append({"type": "diagnostic", "fields": {"severity": "error", "message": name}})
        rows.append({"type": "summary", "fields": fields})
        return rows

    def test_every_finding_bitset_and_proven_clean_zero(self):
        for bits in range(16):
            with self.subTest(bits=bits):
                self.assertEqual(API["completion"](self.report(bits)), (bits.bit_count(), bits))

    def test_operational_failure_and_missing_partial_duplicate_summary(self):
        for rows in [[], [{"type": "log", "fields": {"level": "ERROR", "message": "database missing"}}], self.report(0) * 2, self.report(0) + [{"type": "log", "fields": {"level": "WARN"}}]]:
            with self.subTest(rows=rows), self.assertRaises(AssertionError):
                API["completion"](rows)
        report = self.report(0)
        del report[-1]["fields"]["advisories"]
        with self.assertRaises(AssertionError):
            API["completion"](report)

    def test_truncated_or_malformed_diagnostic_cannot_be_clean(self):
        for mutation in ["missing", "wrong_count", "invalid_type", "malformed", "operational"]:
            rows = copy.deepcopy(self.report(2))
            if mutation == "missing":
                rows.pop(0)
            elif mutation == "wrong_count":
                rows[-1]["fields"]["bans"]["errors"] = 2
            elif mutation == "invalid_type":
                rows[-1]["fields"]["sources"]["warnings"] = False
            elif mutation == "malformed":
                del rows[0]["fields"]["severity"]
            else:
                rows.insert(0, {"type": "log", "fields": {"level": "ERROR", "message": "DB failed"}})
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                API["completion"](rows)


if __name__ == "__main__":
    unittest.main()
