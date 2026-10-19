"""Synthetic validator units; no scanner execution or native qualification evidence."""
import copy
from pathlib import Path
import runpy
import unittest
api=runpy.run_path(str(Path(__file__).resolve().parents[1]/"audit-cargo-geiger-accuracy.py"))

class GeigerReportTests(unittest.TestCase):
    def report(self):
        counters={k:{"safe":0,"unsafe_":0} for k in ["functions","exprs","item_impls","item_traits","methods"]}
        return {"packages":[{"package":{"id":{"name":"fixture","version":"0.0.0","source":{"Path":"file:///fixture"}},"dependencies":[],"dev_dependencies":[],"build_dependencies":[]},"unsafety":{"used":copy.deepcopy(counters),"unused":copy.deepcopy(counters),"forbids_unsafe":False}}],"packages_without_metrics":[],"used_but_not_scanned_files":[]}

    def test_positive_and_proven_zero(self):
        row=self.report();self.assertEqual(api["safety_report"](row),0)
        row["packages"][0]["unsafety"]["used"]["methods"]["unsafe_"]=3
        self.assertEqual(api["safety_report"](row),3)

    def test_incomplete_coverage_and_quick_reports_rejected(self):
        cases=[{}, {"packages":[]}, {"packages":[{"forbids_unsafe":True}],"packages_without_metrics":[]}]
        for key in ["packages_without_metrics","used_but_not_scanned_files"]:
            row=self.report();del row[key];cases.append(row)
        row=self.report();row["packages"]=[];cases.append(row)
        row=self.report();row["packages_without_metrics"]=[row["packages"][0]["package"]["id"]];cases.append(row)
        row=self.report();row["used_but_not_scanned_files"]=["missing.rs"];cases.append(row)
        row=self.report();row["packages"].append(copy.deepcopy(row["packages"][0]));cases.append(row)
        for row in cases:
            with self.subTest(row=row), self.assertRaises((AssertionError, KeyError)): api["safety_report"](row)

    def test_all_five_safe_and_unsafe_counters_require_u64(self):
        for block in ["used","unused"]:
            for category in ["functions","exprs","item_impls","item_traits","methods"]:
                for field in ["safe","unsafe_"]:
                    for bad in [-1,1.5,"0",None,False,2**64]:
                        row=self.report();row["packages"][0]["unsafety"][block][category][field]=bad
                        with self.subTest(block=block,category=category,field=field,bad=bad), self.assertRaises(AssertionError): api["safety_report"](row)
                    row=self.report();row["packages"][0]["unsafety"][block]["functions"][field]=2**64-1;row["packages"][0]["unsafety"][block]["exprs"][field]=1
                    with self.assertRaises(AssertionError): api["safety_report"](row)
