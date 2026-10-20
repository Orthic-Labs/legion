"""Validator units only; literal producer shapes never serve as native evidence."""
import copy
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
api = runpy.run_path(str(ROOT / "scripts/ci/audit-code-long-tail-accuracy.py"))


class LongTailProducerContractUnits(unittest.TestCase):
    def setUp(self):
        # Independent native generic-source known answer, including emitted empty context.
        self.files = {"worker.sh": b"// TODO remove shim\n# FIXME retry\n-- HACK compatibility\n/* XXX review */\n"}
        self.accounting = [{"path": "worker.sh", "extension": "sh", "status": "examined", "bytes": 73,
                            "digest": "sha256:3c53aea795b7fbe29fa8e2e1ad45bff45e603592ef2f8ea425f534bb844b7df5",
                            "analysis": "generic-source"}]
        self.limits = {"maxFileBytes": 1048576, "maxTotalBytes": 67108864, "maxFindings": 500}
        self.producer = {"mode": "self-sourced", "filesExpected": 1, "filesRead": 1,
            "sourceFilesExpected": 1, "sourceFilesRead": 1, "contextFilesExpected": 0, "contextFilesRead": 0,
            "contextBytesRead": 0, "contextAccounting": None, "context": {}, "bytesRead": 73,
            "rules": ["debt-marker", "duplicate-block", "oversized-file"],
            "sourceAccounting": copy.deepcopy(self.accounting), "limits": dict(self.limits),
            "toolDiscovery": [], "toolReceipts": [], "deferredCommands": []}

    def validate(self, producer):
        api["validate_native_producer"](producer, ["worker.sh"], ["worker.sh"], self.accounting, self.files, self.limits)

    def test_native_generic_empty_context_is_required(self):
        self.validate(self.producer)
        for value in (None, [], False, {"sourceSets": []}, {"runtimeQualified": True}):
            altered = copy.deepcopy(self.producer)
            altered["context"] = value
            with self.subTest(context=value), self.assertRaisesRegex(AssertionError, "native source accounting/rules/bounds differ"):
                self.validate(altered)
        altered = copy.deepcopy(self.producer)
        del altered["context"]
        with self.assertRaisesRegex(AssertionError, "native source accounting/rules/bounds differ"):
            self.validate(altered)

    def test_context_does_not_relax_source_bounds_or_tool_evidence(self):
        mutations = [lambda row: row.update(contextFilesRead=1),
                     lambda row: row.update(bytesRead=0),
                     lambda row: row["sourceAccounting"][0].update(digest="sha256:" + "0" * 64),
                     lambda row: row["limits"].update(maxFindings=501),
                     lambda row: row["toolReceipts"].append({"executed": True}),
                     lambda row: row.update(forgedEvidence=True)]
        for index, mutate in enumerate(mutations):
            altered = copy.deepcopy(self.producer)
            mutate(altered)
            with self.subTest(mutation=index), self.assertRaisesRegex(AssertionError, "native source accounting/rules/bounds differ"):
                self.validate(altered)


if __name__ == "__main__":
    unittest.main()
