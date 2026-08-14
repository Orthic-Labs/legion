#!/usr/bin/env python3
"""Phase 5.6 contract tests — REAL transcripts × ALL THREE projections.

Plan requirement (5.6): "Real transcripts from BOTH hosts round-trip through
ALL THREE projections (Handoff, Taste, Insights) producing IDENTICAL event IDs
and byte spans." Plus the explicit constraint: "No phrase-greps."

This test exercises the actual ``parse()`` parser and compares structured
output across projections. It does NOT search the raw transcript text for
strings — it works entirely on the event dicts the parser emits.

Both hosts are real, observed sessions from this machine, frozen as fixtures
(see ``fixtures/README.md``) so the test is deterministic and does not
depend on live session files that are still being appended to.

Run via:
    python3 tools/lib/orthic_transcripts/tests/test_real_transcript_contract.py
or
    python3 -m pytest tools/lib/orthic_transcripts/tests/ -q
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from tools.lib.orthic_transcripts import (  # type: ignore[import-not-found]
        PARSER_DIGEST,
        PARSER_VERSION,
        parse,
    )
except ModuleNotFoundError:
    sys.path.insert(0, str(_HERE.parent.parent))
    from orthic_transcripts import (  # type: ignore[no-redef]
        PARSER_DIGEST,
        PARSER_VERSION,
        parse,
    )

# The three projections the plan names (5.2, 5.3, 5.5).
PROJECTIONS: tuple[str, ...] = ("handoff", "taste", "insights")

CLAUDE_FIXTURE = _HERE / "fixtures" / "claude_real_25aa1534_prefix.jsonl"
CODEX_FIXTURE = _HERE / "fixtures" / "codex_real_019fbc85_prefix.jsonl"

# Tuple of (host_label, fixture_path, expected_host_from_parser) for every
# host we round-trip through. Adding a new host means adding one row here and
# the tests below automatically cover it.
HOST_FIXTURES: tuple[tuple[str, Path, str], ...] = (
    ("claude_code", CLAUDE_FIXTURE, "claude_code"),
    ("codex", CODEX_FIXTURE, "codex"),
)


def _load_all_projections(path: Path) -> dict[str, list[dict]]:
    """Run the parser on ``path`` for every projection and return a map.

    Returns ``{projection_name: [event_dict, ...]}``. The ``"default"`` key
    is what the parser produces when no projection is requested — that is
    the contract baseline the three named projections must equal.
    """
    out: dict[str, list[dict]] = {}
    out["default"] = parse(transcriptPath=str(path))
    for name in PROJECTIONS:
        out[name] = parse(transcriptPath=str(path), projection=name)
    return out


class TestRealTranscriptContract(unittest.TestCase):
    """Real transcripts × all three projections = identical event ids / spans."""

    # ---- fixtures exist ----

    def test_claude_fixture_exists_and_is_nontrivial(self):
        self.assertTrue(CLAUDE_FIXTURE.is_file(), f"missing {CLAUDE_FIXTURE}")
        # Sanity: real transcripts are not toy one-liners.
        self.assertGreater(CLAUDE_FIXTURE.stat().st_size, 10_000)

    def test_codex_fixture_exists_and_is_nontrivial(self):
        self.assertTrue(CODEX_FIXTURE.is_file(), f"missing {CODEX_FIXTURE}")
        self.assertGreater(CODEX_FIXTURE.stat().st_size, 10_000)

    # ---- per-host: identity equality across projections ----

    def test_claude_event_ids_identical_across_all_three_projections(self):
        proj_events = _load_all_projections(CLAUDE_FIXTURE)
        default_ids = sorted(ev["eventId"] for ev in proj_events["default"])
        self.assertGreater(len(default_ids), 0, "claude fixture produced no events")
        for name in PROJECTIONS:
            other_ids = sorted(ev["eventId"] for ev in proj_events[name])
            self.assertEqual(
                other_ids,
                default_ids,
                f"claude projection={name!r} produced different event ids than default",
            )

    def test_codex_event_ids_identical_across_all_three_projections(self):
        proj_events = _load_all_projections(CODEX_FIXTURE)
        default_ids = sorted(ev["eventId"] for ev in proj_events["default"])
        self.assertGreater(len(default_ids), 0, "codex fixture produced no events")
        for name in PROJECTIONS:
            other_ids = sorted(ev["eventId"] for ev in proj_events[name])
            self.assertEqual(
                other_ids,
                default_ids,
                f"codex projection={name!r} produced different event ids than default",
            )

    def test_claude_byte_spans_identical_across_all_three_projections(self):
        proj_events = _load_all_projections(CLAUDE_FIXTURE)
        # Compare the full ordered sequence of byte spans, not just the set —
        # projections must preserve order, not merely the span coverage.
        default_spans = [
            (ev["rowIndex"], ev["byteStart"], ev["byteEnd"], ev["blockIndex"], ev["sequence"])
            for ev in proj_events["default"]
        ]
        for name in PROJECTIONS:
            other_spans = [
                (ev["rowIndex"], ev["byteStart"], ev["byteEnd"], ev["blockIndex"], ev["sequence"])
                for ev in proj_events[name]
            ]
            self.assertEqual(
                other_spans,
                default_spans,
                f"claude projection={name!r} changed byte spans / ordering",
            )

    def test_codex_byte_spans_identical_across_all_three_projections(self):
        proj_events = _load_all_projections(CODEX_FIXTURE)
        default_spans = [
            (ev["rowIndex"], ev["byteStart"], ev["byteEnd"], ev["blockIndex"], ev["sequence"])
            for ev in proj_events["default"]
        ]
        for name in PROJECTIONS:
            other_spans = [
                (ev["rowIndex"], ev["byteStart"], ev["byteEnd"], ev["blockIndex"], ev["sequence"])
                for ev in proj_events[name]
            ]
            self.assertEqual(
                other_spans,
                default_spans,
                f"codex projection={name!r} changed byte spans / ordering",
            )

    # ---- per-host: projections share identity, but each event's own kind/text/flags are intact ----

    def test_claude_each_event_carries_required_contract_fields(self):
        proj_events = _load_all_projections(CLAUDE_FIXTURE)
        required_event_fields = (
            "eventId",
            "rowIndex",
            "byteStart",
            "byteEnd",
            "blockIndex",
            "sequence",
            "kind",
            "host",
            "sessionId",
            "transcriptId",
            "parserDigest",
        )
        required_flag_fields = ("synthetic", "meta", "privateReasoningOmitted", "redacted")
        for name, events in proj_events.items():
            for ev in events:
                for field in required_event_fields:
                    self.assertIn(field, ev, f"claude/{name} missing {field!r}")
                for field in required_flag_fields:
                    self.assertIn(field, ev, f"claude/{name} missing flag {field!r}")
                    self.assertIsInstance(ev[field], bool, f"claude/{name} flag {field!r} not bool")

    def test_codex_each_event_carries_required_contract_fields(self):
        proj_events = _load_all_projections(CODEX_FIXTURE)
        required_event_fields = (
            "eventId",
            "rowIndex",
            "byteStart",
            "byteEnd",
            "blockIndex",
            "sequence",
            "kind",
            "host",
            "sessionId",
            "transcriptId",
            "parserDigest",
        )
        required_flag_fields = ("synthetic", "meta", "privateReasoningOmitted", "redacted")
        for name, events in proj_events.items():
            for ev in events:
                for field in required_event_fields:
                    self.assertIn(field, ev, f"codex/{name} missing {field!r}")
                for field in required_flag_fields:
                    self.assertIn(field, ev, f"codex/{name} missing flag {field!r}")
                    self.assertIsInstance(ev[field], bool, f"codex/{name} flag {field!r} not bool")

    # ---- prefix receipts match PARSER_DIGEST for both hosts × all projections ----

    def test_prefix_receipts_for_both_hosts_bind_parser_digest(self):
        for label, path, _ in HOST_FIXTURES:
            receipt = parse(transcriptPath=str(path), asPrefixReceipt=True)
            self.assertEqual(
                receipt["host"],
                label,
                f"prefix receipt host mismatch for {label}",
            )
            self.assertEqual(
                receipt["parserDigest"],
                PARSER_DIGEST,
                f"prefix receipt parserDigest != PARSER_DIGEST for {label}",
            )
            self.assertEqual(receipt["parserVersion"], PARSER_VERSION)
            self.assertTrue(receipt["prefixDigest"].startswith("sha256:"))
            self.assertGreater(receipt["prefixLength"], 0)
            self.assertNotEqual(receipt["sessionId"], "", f"{label} sessionId is empty")

    # ---- byte-faithful proof: the events the parser emits point at the actual rows in the file ----

    def test_byte_spans_for_both_hosts_point_into_the_actual_file(self):
        """Every emitted event's (byteStart, byteEnd) must slice a JSONL row
        out of the source file that round-trips through json.loads.

        This is the non-grep proof that the parser is reading the file
        byte-correctly, not searching for substrings.
        """
        for _label, path, _ in HOST_FIXTURES:
            events = parse(transcriptPath=str(path))
            self.assertGreater(len(events), 0, f"{path.name} produced no events")
            raw = path.read_bytes()
            for ev in events:
                start = ev["byteStart"]
                end = ev["byteEnd"]
                # Slicing must lie inside the file and end strictly after start.
                self.assertGreaterEqual(start, 0)
                self.assertLessEqual(end, len(raw))
                self.assertGreater(end, start, "byte span must be non-empty")
                # The slice must parse as one complete JSONL row.
                row_bytes = raw[start:end]
                try:
                    obj = json.loads(row_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    self.fail(f"{path.name}: row at [{start},{end}) not JSON: {exc}")
                self.assertIsInstance(obj, dict, "row at span is not a JSON object")

    # ---- deterministic event ids: re-parsing the same file yields identical ids ----

    def test_event_ids_are_deterministic_across_repeated_parses(self):
        """Two parses of the same fixture must yield identical event ids in
        identical order. If this fails, the contract identity guarantee is
        broken for downstream caches / handoff state.
        """
        for _label, path, _ in HOST_FIXTURES:
            first = parse(transcriptPath=str(path))
            second = parse(transcriptPath=str(path))
            self.assertEqual(
                [ev["eventId"] for ev in first],
                [ev["eventId"] for ev in second],
                f"{path.name}: event ids non-deterministic across parses",
            )

    # ---- negative-shape proof: NOT a phrase-grep ----

    def test_test_does_not_use_phrase_greps(self):
        """Constraint from plan 5.6: "No phrase-greps." Encode the rule
        structurally so future edits can't silently regress.

        The contract test compares structured event dicts. It must not
        contain string-matching against the raw transcript outside the
        ``assertIsInstance(json.loads(...))`` byte-faithful check. We
        detect regressions by introspecting this file's source.
        """
        # AST scan instead of textual — avoids false positives from this very
        # test describing what it forbids, and catches re.search / regex
        # literals anywhere in the file.
        import ast
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        forbidden_calls = {"search", "match", "findall", "finditer", "fullmatch"}
        offenders: list[str] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.func.attr in forbidden_calls
            ):
                offenders.append(f"line {node.lineno}: re.{node.func.attr}(")
            if isinstance(node, ast.Compare):
                # Forbid `x in raw_transcript_text` shape (substring containment).
                for comparator in node.comparators:
                    if isinstance(comparator, ast.Name) and comparator.id in {
                        "raw_text",
                        "transcript_text",
                        "raw_transcript",
                    }:
                        offenders.append(
                            f"line {node.lineno}: substring-containment against {comparator.id}"
                        )
        self.assertEqual(
            offenders,
            [],
            "contract test regressed to phrase-grep: " + ", ".join(offenders),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)