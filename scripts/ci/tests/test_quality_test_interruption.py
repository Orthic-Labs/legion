"""Parser/tamper units only; synthetic shapes carry no broker trust or qualification."""
import copy
from pathlib import Path
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[3]
api = runpy.run_path(str(ROOT / "scripts/ci/audit-quality-test-accuracy.py"))


def process(control="timeout", signal=15, hard=True):
    state = "timeout" if control == "timeout" else "cancelled"
    case = {"caseId": control, "events": [{}, {"cancellation": {"delayMs":1500,"fired":True}}]}
    request = {"timeoutMs": 2500}
    receipt = {"state": state, "complete": False, "policy": {"allowed": True}, "gaps": [state],
               "exitCode": 0 if signal is None else None, "signal": signal,
               "processTree": {"started": True, "terminated": True, "reaped": True, "hardKilled": hard,
                   "detail": state + ": cooperative termination then bounded hard cleanup; term_errno=None, kill_errno=None, post_reap_probe_errno=None, post_reap_group_absent=None"},
               "timing": {"startedAtMs": 1000, "completedAtMs": 5500, "durationMs": 4500}}
    return case, request, receipt


def retained(control="timeout"):
    """Pure parser input, with no files, signatures, enrolled host or trusted record."""
    case, request, receipt = process(control)
    cwd = "/scratch/test-copy-1"
    event = {"originalRequest": dict(request, args=["cargo", "test"], cwd=cwd),
             "executedRequest": request, "receipt": receipt}
    if control == "cancellation":
        event["cancellation"] = {"delayMs":1500,"fired":True}
    probe = {"receipt":{"state":"completed","complete":True,"policy":{"allowed":True}}}
    case["events"] = [probe, event]
    receipt.update(receiptId="receipt:submit", requestId="submit", cwd=cwd)
    reason = "cancelled-after-submit-launch" if control == "cancellation" else "cancelled-or-timed-out"
    native = {"state":"internal","complete":False,"processTree":{"detail":"launch and cleanup state unobserved"}} if control == "cancellation" else copy.deepcopy(receipt)
    case.update(frozenProvider={"bounds":{"timeoutMs":2500}}, copyPathsAfter={cwd:True},
                nativeResult={"coverage":{"gaps":["disposable-copy-incomplete:" + reason]},
                    "details":{"testCommandResolution":{"reason":reason}, "disposableCopy":{"copyPath":cwd}, "executionReceipt":native}})
    streams = [("request-digest", b"", b"", probe), ("cargo", b"", b"rightkit: request native-job-1\n", event)]
    if control == "timeout":
        streams += [(op, b"", b"", {"originalRequest":{"args":[op,"native-job-1"]}}) for op in ("cancel","status")]
    return case, [row[0] for row in streams], streams


class QualityTestInterruptionUnits(unittest.TestCase):
    def test_native_terminal_status_parser_accepts_only_bounded_termination(self):
        for control in ("timeout", "cancellation"):
            for signal, hard in ((None, False), (15, False), (15, True), (9, True)):
                api["interruption_process"](*process(control, signal, hard))

    def test_failed_submit_or_retained_copy_cannot_stand_in_for_interruption(self):
        for state in ("failed", "completed", "output_limited", "kill_failed", "spawn_failed", "cancelled"):
            case, request, receipt = process()
            receipt.update(state=state, gaps=[state])
            case["copyPathsAfter"] = {"/scratch/test-copy-1": True}
            with self.assertRaises(AssertionError):
                api["interruption_process"](case, request, receipt)

    def test_unrelated_signals_unreaped_or_unknown_cleanup_are_refused(self):
        mutations = (
            lambda r: r.update(signal=11),
            lambda r: r.update(signal=9, processTree=dict(r["processTree"], hardKilled=False)),
            lambda r: r.update(signal=15, exitCode=0),
            lambda r: r.update(signal=None, exitCode=None),
            lambda r: r["processTree"].update(reaped=False),
            lambda r: r["processTree"].update(terminated=False),
            lambda r: r["processTree"].update(detail="normal exit: process-group cleanup"),
            lambda r: r["timing"].update(durationMs=1),
            lambda r: r.update(complete=True),
            lambda r: r["policy"].update(allowed=False),
        )
        for mutate in mutations:
            case, request, receipt = process()
            mutate(receipt)
            with self.assertRaises(AssertionError):
                api["interruption_process"](case, request, receipt)

    def test_timeout_must_reach_bound_and_cancellation_trigger_must_fire(self):
        case, request, receipt = process()
        receipt["timing"] = {"startedAtMs":1000,"completedAtMs":1100,"durationMs":100}
        with self.assertRaises(AssertionError):
            api["interruption_process"](case, request, receipt)
        case, request, receipt = process("cancellation")
        case["events"][1]["cancellation"]["fired"] = False
        with self.assertRaises(AssertionError):
            api["interruption_process"](case, request, receipt)
        case, request, receipt = process("nonempty-pass")
        with self.assertRaises(AssertionError):
            api["interruption_process"](case, request, receipt)

    def test_missing_native_submit_and_generic_retention_fail_before_proof(self):
        case = {"caseId":"timeout", "copyPathsAfter":{"/scratch/test-copy-1":True}}
        for operations in ([], ["cargo"], ["request-digest", "cargo", "status"]):
            with self.assertRaises(AssertionError):
                api["verify_interrupted"](copy.deepcopy(case), operations, [])

    def test_native_retention_parser_binds_actual_interruption_and_command_chain(self):
        for control in ("timeout", "cancellation"):
            api["verify_interrupted"](*retained(control))
        mutations = (
            lambda c, o, s: s[1][3]["receipt"].update(state="failed", signal=None, exitCode=1, gaps=["failed"]),
            lambda c, o, s: c["nativeResult"]["details"]["testCommandResolution"].update(reason="rightkit-submit-process-unconfirmed"),
            lambda c, o, s: s[2][3]["originalRequest"].update(args=["cancel","unrelated-job"]),
            lambda c, o, s: c["nativeResult"]["details"]["executionReceipt"].update(requestId="unrelated-submit"),
            lambda c, o, s: c["nativeResult"]["details"]["disposableCopy"].update(copyPath="/scratch/unrelated-copy"),
            lambda c, o, s: o.__delitem__(slice(2, None)),
        )
        for mutate in mutations:
            case, operations, streams = retained()
            mutate(case, operations, streams)
            with self.assertRaises(AssertionError):
                api["verify_interrupted"](case, operations, streams)
