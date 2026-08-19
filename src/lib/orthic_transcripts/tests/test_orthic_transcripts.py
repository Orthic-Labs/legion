#!/usr/bin/env python3
"""Self-test for orthic_transcripts (plan 5.1).

Run via:
    python3 -m pytest tools/lib/orthic_transcripts/tests/ -q
or
    python3 tools/lib/orthic_transcripts/tests/test_orthic_transcripts.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
# tools/lib/orthic_transcripts/tests -> tools/lib/orthic_transcripts -> tools/lib -> tools -> repo_root
_REPO_ROOT = _HERE.parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Fall back to direct package import when invoked from the repo root.
try:
    from tools.lib.orthic_transcripts import (  # type: ignore[import-not-found]
        PARSER_DIGEST,
        PARSER_VERSION,
        TranscriptEventV1,
        parse,
        parse_source_events,
        resolve_session,
    )
except ModuleNotFoundError:
    sys.path.insert(0, str(_HERE.parent.parent))
    from orthic_transcripts import (  # type: ignore[no-redef]
        PARSER_DIGEST,
        PARSER_VERSION,
        TranscriptEventV1,
        parse,
        parse_source_events,
        resolve_session,
    )


def _write_transcript(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = b"".join(
        (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
        for row in rows
    )
    path.write_bytes(raw)


SHARED_TRANSCRIPT: list[dict] = [
    {
        "type": "user",
        "sessionId": "shared-abc",
        "cwd": "/Users/example/sample-project",
        "timestamp": "2026-08-04T12:00:01Z",
        "message": {"role": "user", "content": "Find the order total function."},
    },
    {
        "type": "assistant",
        "sessionId": "shared-abc",
        "cwd": "/Users/example/sample-project",
        "timestamp": "2026-08-04T12:00:02Z",
        "message": {
            "role": "assistant",
            "content": [
                {"type": "tool_use", "id": "call_001", "name": "Read", "input": {"path": "src/checkout.ts"}},
            ],
        },
    },
    {
        "type": "user",
        "sessionId": "shared-abc",
        "cwd": "/Users/example/sample-project",
        "timestamp": "2026-08-04T12:00:03Z",
        "message": {
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "call_001", "content": "export function total()"},
            ],
        },
    },
    {
        "type": "assistant",
        "sessionId": "shared-abc",
        "cwd": "/Users/example/sample-project",
        "timestamp": "2026-08-04T12:00:04Z",
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": "Found total in checkout.ts"}],
        },
    },
]


CLASS_PRIORITY_TRANSCRIPT: list[dict] = []
CLASS_PRIORITY_TRANSCRIPT.append({
    "type": "user",
    "sessionId": "class-priority",
    "cwd": "/Users/example/sample-project",
    "timestamp": "2026-08-04T12:00:00Z",
    "message": {"role": "user", "content": "Please fix the build."},
})
for i in range(1, 8):
    is_failure = (i == 1)
    CLASS_PRIORITY_TRANSCRIPT.append({
        "type": "assistant",
        "sessionId": "class-priority",
        "cwd": "/Users/example/sample-project",
        "timestamp": f"2026-08-04T12:00:{i*2:02d}Z",
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": f"call_{i:03d}",
                    "name": "Write" if is_failure else "Read",
                    "input": {"path": f"src/file_{i}.ts"},
                },
            ],
        },
    })
    CLASS_PRIORITY_TRANSCRIPT.append({
        "type": "user",
        "sessionId": "class-priority",
        "cwd": "/Users/example/sample-project",
        "timestamp": f"2026-08-04T12:00:{i*2+1:02d}Z",
        "message": {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": f"call_{i:03d}",
                    "content": "ENOENT: file not found" if is_failure else "export const ok = 1;",
                    "is_error": is_failure,
                },
            ],
        },
    })


class TestTranscriptParser(unittest.TestCase):
    def test_shared_transcript_has_unique_event_ids(self):
        with tempfile.TemporaryDirectory(prefix="orthic-") as directory:
            path = Path(directory) / "shared.jsonl"
            _write_transcript(path, SHARED_TRANSCRIPT)
            events = parse(transcriptPath=str(path))
            self.assertGreater(len(events), 0)
            ids = [ev["eventId"] for ev in events]
            self.assertEqual(len(ids), len(set(ids)))

    def test_each_event_has_byte_spans_and_flags(self):
        with tempfile.TemporaryDirectory(prefix="orthic-") as directory:
            path = Path(directory) / "shared.jsonl"
            _write_transcript(path, SHARED_TRANSCRIPT)
            events = parse(transcriptPath=str(path))
            for ev in events:
                for field in ("rowIndex", "byteStart", "byteEnd", "blockIndex", "sequence"):
                    self.assertIsInstance(ev[field], int)
                    self.assertGreaterEqual(ev[field], 0)
                for flag in ("synthetic", "meta", "privateReasoningOmitted", "redacted"):
                    self.assertIsInstance(ev[flag], bool)

    def test_projections_share_event_ids(self):
        with tempfile.TemporaryDirectory(prefix="orthic-") as directory:
            path = Path(directory) / "shared.jsonl"
            _write_transcript(path, SHARED_TRANSCRIPT)
            default = parse(transcriptPath=str(path))
            taste = parse(transcriptPath=str(path), projection="taste")
            insights = parse(transcriptPath=str(path), projection="insights")
            default_ids = {ev["eventId"] for ev in default}
            taste_ids = {ev["eventId"] for ev in taste}
            insights_ids = {ev["eventId"] for ev in insights}
            self.assertEqual(taste_ids, default_ids)
            self.assertEqual(insights_ids, default_ids)

    def test_prefix_receipt_shape(self):
        with tempfile.TemporaryDirectory(prefix="orthic-") as directory:
            path = Path(directory) / "shared.jsonl"
            _write_transcript(path, SHARED_TRANSCRIPT)
            receipt = parse(transcriptPath=str(path), asPrefixReceipt=True)
            self.assertEqual(receipt["host"], "claude_code")
            self.assertEqual(receipt["sessionId"], "shared-abc")
            self.assertEqual(receipt["transcriptId"], "shared")
            self.assertTrue(receipt["prefixDigest"].startswith("sha256:"))
            self.assertTrue(receipt["parserDigest"].startswith("sha256:"))
            self.assertEqual(receipt["parserVersion"], PARSER_VERSION)
            self.assertEqual(receipt["parserDigest"], PARSER_DIGEST)

    def test_class_priority_admission_keeps_early_failure(self):
        with tempfile.TemporaryDirectory(prefix="orthic-") as directory:
            path = Path(directory) / "class.jsonl"
            _write_transcript(path, CLASS_PRIORITY_TRANSCRIPT)
            events = parse(transcriptPath=str(path), projection="handoff")
            self.assertGreater(len(events), 0)
            # The first call_001 is the unresolved failure. Plan 5.2 says it
            # must survive class-priority admission even when later pairs
            # are successful read-only ops that get squeezed by the cap.
            failure_kept = any(
                ev.get("classification") == "unresolved_failure"
                and ev.get("call_id") == "call_001"
                for ev in events
            )
            self.assertTrue(failure_kept, "early unresolved failure dropped")

    def test_resolve_session_exact_match_only(self):
        # Substring bug fix: requesting "abc" must NOT match a candidate
        # whose sessionId is "different-session" just because "abc" appears
        # inside the path name "xyz-abc-def.jsonl".
        match = resolve_session(
            requestedSessionId="abc",
            candidates=[{"path": "/tmp/xyz-abc-def.jsonl", "sessionId": "different-session"}],
        )
        self.assertIsNone(match)
        # Exact-match resolution still works.
        match = resolve_session(
            requestedSessionId="abc",
            candidates=[{"path": "/tmp/abc.jsonl", "sessionId": "abc"}],
        )
        self.assertIsNotNone(match)
        self.assertEqual(match["sessionId"], "abc")

    def test_planning_tool_not_classified_as_mutation(self):
        """Plan 5.2 explicit fix: TodoWrite / update_plan must be decisions."""
        with tempfile.TemporaryDirectory(prefix="orthic-") as directory:
            path = Path(directory) / "planning.jsonl"
            rows = [
                {
                    "type": "assistant",
                    "sessionId": "plan",
                    "cwd": "/Users/example/sample-project",
                    "timestamp": "2026-08-04T12:00:00Z",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "plan-1",
                                "name": "TodoWrite",
                                "input": {"todos": [{"content": "a", "status": "pending"}]},
                            },
                        ],
                    },
                },
            ]
            _write_transcript(path, rows)
            events = parse(transcriptPath=str(path))
            self.assertGreater(len(events), 0)
            self.assertEqual(events[0]["classification"], "decision_or_constraint")

    def test_call_id_occurrence_pairing(self):
        """Same call_id appearing multiple times yields separate events.

        The (call_id, occurrence) pair (plan 5.2) means a reused call_id
        gets a fresh occurrence counter. The fingerprint-set dedup catches
        identical (kind, call_id, occurrence, text) tuples; different text
        keeps the events distinct.
        """
        with tempfile.TemporaryDirectory(prefix="orthic-") as directory:
            path = Path(directory) / "repeat.jsonl"
            rows = [
                {
                    "type": "assistant",
                    "sessionId": "repeat",
                    "cwd": "/Users/example/sample-project",
                    "timestamp": "2026-08-04T12:00:00Z",
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "tool_use", "id": "x", "name": "Read", "input": {}}],
                    },
                },
                {
                    "type": "user",
                    "sessionId": "repeat",
                    "cwd": "/Users/example/sample-project",
                    "timestamp": "2026-08-04T12:00:01Z",
                    "message": {
                        "role": "user",
                        "content": [{"type": "tool_result", "tool_use_id": "x", "content": "first"}],
                    },
                },
                {
                    "type": "assistant",
                    "sessionId": "repeat",
                    "cwd": "/Users/example/sample-project",
                    "timestamp": "2026-08-04T12:00:02Z",
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "tool_use", "id": "x", "name": "Read", "input": {}}],
                    },
                },
                {
                    "type": "user",
                    "sessionId": "repeat",
                    "cwd": "/Users/example/sample-project",
                    "timestamp": "2026-08-04T12:00:03Z",
                    "message": {
                        "role": "user",
                        "content": [{"type": "tool_result", "tool_use_id": "x", "content": "second"}],
                    },
                },
            ]
            _write_transcript(path, rows)
            events = parse(transcriptPath=str(path))
            occurrences = [ev.get("occurrence") for ev in events if ev.get("call_id") == "x"]
            # Two tool_use (occurrence 0, 2) + two tool_result (occurrence 1, 3).
            # The exact ordering depends on host adapter output; the contract
            # is that occurrence counter monotonically increases per call_id.
            self.assertEqual(sorted(occurrences), [0, 1, 2, 3])
            # And (call_id, occurrence) is unique per call_id.
            self.assertEqual(len(occurrences), len(set(occurrences)))

    def test_parser_digest_stable(self):
        # The parser implementation digest is content-only; identical code
        # yields identical digest. We just confirm it matches the constant.
        self.assertTrue(PARSER_DIGEST.startswith("sha256:"))
        self.assertEqual(len(PARSER_DIGEST), len("sha256:") + 64)

    def test_aliased_entry_points(self):
        with tempfile.TemporaryDirectory(prefix="orthic-") as directory:
            path = Path(directory) / "shared.jsonl"
            _write_transcript(path, SHARED_TRANSCRIPT)
            snake = parse(transcriptPath=str(path))
            camel = TranscriptEventV1(transcriptPath=str(path))
            self.assertEqual(
                [ev["eventId"] for ev in snake],
                [ev["eventId"] for ev in camel],
            )

    def test_source_events_preserve_uncapped_original_sequence(self):
        with tempfile.TemporaryDirectory(prefix="orthic-") as directory:
            path = Path(directory) / "source.jsonl"
            rows = [
                {"type": "user", "sessionId": "source", "message": {"content": f"message {i}"}}
                for i in range(9)
            ]
            _write_transcript(path, rows)
            capped = parse(transcriptPath=str(path))
            source = parse_source_events(transcriptPath=str(path))
            self.assertEqual(len(source), 9)
            self.assertLess(len(capped), len(source))
            self.assertEqual([event["sequence"] for event in source], list(range(1, 10)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
