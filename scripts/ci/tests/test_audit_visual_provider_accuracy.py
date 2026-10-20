"""Validator controls; synthetic state never establishes browser provenance."""
from pathlib import Path
import runpy
import unittest

API = runpy.run_path(str(Path(__file__).resolve().parents[1] / "audit-visual-provider-accuracy.py"))


class VisualFrameEvidenceTests(unittest.TestCase):
    def test_real_frame_completion_requires_both_callbacks(self):
        frames = {"rafAvailable": True, "frameCallbacks": 2, "frameProbeComplete": True, "readyState": "complete"}
        API["frame_completion"]({"animationFrames": frames})
        for changed in ({}, {"frameCallbacks": 1}, {"frameCallbacks": True},
                        {"frameProbeComplete": False}, {"rafAvailable": False}, {"readyState": "loading"}):
            with self.assertRaises(AssertionError):
                API["frame_completion"]({} if not changed else {"animationFrames": {**frames, **changed}})

    def test_poll_count_may_vary_but_admissions_remain_exact(self):
        captured = {"url": "http://127.0.0.1:1234/baseline/index.html"}
        common = {"allowed": True, "sessionId": "control", "url": captured["url"]}
        fixed = [{**common, "action": "Navigate", "detail": None}] + [
            {**common, "action": "Eval", "detail": API[name]}
            for name in ("READY", "START_ANIMATION_FRAMES", "HIGH_ENTROPY_UA", "OBSERVE")]
        poll = {**common, "action": "Eval", "detail": API["ANIMATION_STATE"]}
        for count in (1, 4):
            API["capture_admissions"](captured, fixed + [poll] * count, "control")
        for invalid in (fixed, fixed + [poll, {**poll, "detail": "true"}],
                        fixed + [poll, fixed[2]], fixed + [{**poll, "allowed": False}]):
            with self.assertRaises(AssertionError):
                API["capture_admissions"](captured, invalid, "control")


if __name__ == "__main__":
    unittest.main()
