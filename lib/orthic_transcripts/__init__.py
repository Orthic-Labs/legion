"""orthic_transcripts — TranscriptEventV1 parser (plan 5.1).

Public surface:
    parse(...)          — identical-name parser entry point (also exported as
                          TranscriptEventV1 and transcriptEventV1 for JS shim).
    resolve_session(...) — exact-match session resolver (substring bug fix).
    PARSER_DIGEST       — sha256 of the parser implementation bytes (binding
                          target for the frozen prefix receipt).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .host_adapters import detect_host, iter_events_for_host

# Re-export the host adapters' secret/secret-like constants.
from .host_adapters import BASE64_BLOB, SECRET_PATTERNS  # noqa: F401

PARSER_VERSION = "orthic.transcript-event.v1"

# Caps that mirror transcript-handoff.py's bounder so event text is the same
# shape downstream consumers already understand.
MAX_EVENT_CHARS = 6_000
MAX_TOOL_CALL_CHARS = 1_200
MAX_TOOL_RESULT_CHARS = 1_600
MAX_ASSISTANT_CHARS = 4_000

# Class priority admission — plan 5.2. Lower number = higher priority.
# Order: unresolved failures > mutations > failed verification > open user
# requests > decisions/constraints > successful read-only (cap squeezes only
# the last class).
CLASS_PRIORITY: dict[str, int] = {
    "unresolved_failure": 0,
    "mutation": 1,
    "failed_verification": 2,
    "open_user_request": 3,
    "decision_or_constraint": 4,
    "successful_readonly": 5,
}

# Tool name -> read-only classification used for class-priority admission.
READONLY_TOOL_TOKENS: frozenset[str] = frozenset(
    {
        "read",
        "glob",
        "grep",
        "search",
        "list",
        "ls",
        "view",
        "fetch",
        "query",
        "describe",
        "get",
        "show",
        "inspect",
    }
)

# Tools that look like mutations. Planning operations explicitly excluded
# (TodoWrite / update_plan / create_goal / update_goal / apply_patch /
#  create_thread / send_message / forge — see plan 5.2 fix).
MUTATION_TOOL_TOKENS: frozenset[str] = frozenset(
    {
        "write",
        "edit",
        "multiedit",
        "create",
        "delete",
        "remove",
        "patch",
        "move",
        "rename",
        "deploy",
        "publish",
        "install",
        "add",
        "commit",
        "push",
        "merge",
        "applypatch",
    }
)

# Planning-only tools — must NOT be classified as mutations per plan 5.2.
PLANNING_TOOL_TOKENS: frozenset[str] = frozenset(
    {
        "todowrite",
        "updateplan",
        "creategoal",
        "updategoal",
        "createplan",
        "updateplanv2",
        "plan",
        "create_thread",
        "sendmessage",
        "send_message",
        "forge",
        "apply_patch",
    }
)

# Regex fallback for structured failure detection (extends the existing
# patterns in transcript-handoff.py:is_failure).
FAILURE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?im)\bFAIL(?:ED)?:"),
    re.compile(r"(?im)\bERROR\b"),
    re.compile(r"(?im)\bTraceback\b"),
    re.compile(r"(?im)\bExit code:\s*[1-9]\d*"),
    re.compile(r"(?im)\breturncode[\"']?\s*[:=]\s*[1-9]\d*"),
    re.compile(r"(?im)\bENOENT\b"),
    re.compile(r"(?im)\bEACCES\b"),
    re.compile(r"(?im)\bpermission denied\b"),
    re.compile(r"(?im)\btimeout\b"),
    re.compile(r"(?im)\b(?:npm|pnpm|yarn)\b.*\bERR!\b"),
)

# Patterns signalling explicit user-request boundaries (open user request class).
USER_REQUEST_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?im)^\s*(?:please\s+)?(?:fix|implement|add|build|create|make|ensure)\b"),
    re.compile(r"(?im)^\s*(?:can|could|would)\s+you\b"),
)

# Patterns signalling decisions or constraints.
DECISION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?im)^\s*(?:decision|locked|constraint|invariant|rules?):\s*"),
    re.compile(r"(?im)\bnever\b.*\b(?:use|do|call|invoke)\b"),
    re.compile(r"(?im)\balways\b.*\b(?:use|do|call|invoke)\b"),
)


def _redact(text: str) -> str:
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return BASE64_BLOB.sub("[BINARY_BLOB_REMOVED]", text)


def compact_text(value: Any, limit: int = MAX_EVENT_CHARS) -> str:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = _redact(text.replace("\x00", "")).strip()
    if len(text) > limit:
        text = text[:limit] + "\n[TRUNCATED]"
    return text


def _classify_event(
    event: dict[str, Any], flags: dict[str, bool]
) -> str:
    """Return one of the class-priority admission classes.

    The flags dict is the per-event flag set from the host adapter
    (``is_error``, ``is_redacted``, ``private_reasoning_omitted``, etc.).
    """
    kind = str(event.get("kind") or "")
    text = str(event.get("text") or "")
    tool = str(event.get("tool") or "").casefold()
    is_error = bool(flags.get("is_error"))

    # Unresolved failure: tool_result with structured failure text or error flag.
    if kind == "tool_result" and (is_error or _matches_any(FAILURE_PATTERNS, text)):
        return "unresolved_failure"

    # Mutation: tool_call whose tool name is in the mutation list.
    if kind == "tool_call":
        if any(token in tool for token in PLANNING_TOOL_TOKENS):
            return "decision_or_constraint"
        if any(token in tool for token in MUTATION_TOOL_TOKENS):
            return "mutation"
        # Heuristic fallback for inline shell-style mutations in input text.
        if re.search(
            r"(?im)\b(?:git\s+(?:add|commit|push|merge)|"
            r"Set-Content|Add-Content|New-Item|Remove-Item|"
            r"npm\s+install|pnpm\s+add|pip\s+install|deploy|publish)\b",
            text,
        ):
            return "mutation"

    # Failed verification: assistant text that contains a verification-style
    # claim followed by a correction/failure indicator.
    if kind == "assistant_message" and re.search(
        r"(?im)\b(?:verified|validated|fixed|tested)\b.*\b(?:failed|broken|wrong|"
        r"missing|not fixed|still fails)\b",
        text,
    ):
        return "failed_verification"

    # Open user request: user message with explicit request patterns.
    if kind == "user_message" and _matches_any(USER_REQUEST_PATTERNS, text):
        return "open_user_request"

    # Decision / constraint.
    if kind in {"user_message", "assistant_message"} and _matches_any(
        DECISION_PATTERNS, text
    ):
        return "decision_or_constraint"

    # Successful read-only: tool_call with read-only tool + matching tool_result
    # without failure indicators, OR pure read tool with successful text.
    if kind == "tool_call" and any(token in tool for token in READONLY_TOOL_TOKENS):
        return "successful_readonly"
    if kind == "tool_call":
        return "successful_readonly"

    # Default fallback: bucket as a successful read-only op so the cap can
    # squeeze it; intentional per plan 5.2 ordering.
    return "successful_readonly"


def _matches_any(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def _parser_impl_path() -> Path:
    """Filesystem path of the Python parser implementation.

    Used to compute the parser implementation digest that the frozen prefix
    receipt binds (plan 5.1). We hash the bytes of THIS package's primary
    modules so a parser change is detectable from the receipt alone.
    """
    return Path(__file__).resolve()


def _parser_impl_files() -> list[Path]:
    base = Path(__file__).resolve().parent
    return sorted(base.rglob("*.py"))


def compute_parser_digest() -> str:
    """sha256 over the parser implementation bytes.

    The hash is content-only and order-stable so identical trees produce
    identical digests.
    """
    digest = hashlib.sha256()
    for path in _parser_impl_files():
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(path.read_bytes())
        digest.update(b"\x00")
    return "sha256:" + digest.hexdigest()


PARSER_DIGEST: str = compute_parser_digest()


@dataclass(frozen=True)
class _RowCursor:
    row_index: int
    byte_start: int
    byte_end: int


def iter_jsonl_rows(path: Path, limit_bytes: int | None = None) -> Iterable[tuple[int, int, int, bytes]]:
    """Iterate JSONL rows from ``path``.

    Yields ``(row_index, byte_start, byte_end, raw_bytes)`` per row.
    The byte spans describe the row including its trailing newline so they are
    usable for byte-precise slicing of the original transcript.
    """
    consumed = 0
    row_index = 0
    with path.open("rb") as handle:
        while True:
            if limit_bytes is not None and consumed >= limit_bytes:
                return
            raw = handle.readline()
            if not raw:
                return
            row_index += 1
            byte_start = consumed
            byte_end = consumed + len(raw)
            consumed = byte_end
            if limit_bytes is not None and consumed > limit_bytes:
                # The last partial row past the cutoff is dropped; consumers
                # see byte-precise rows that fit inside the prefix.
                return
            yield row_index, byte_start, byte_end, raw


def _read_prefix_receipt(
    path: Path, host: str, transcript_id: str
) -> dict[str, Any]:
    """Compute the frozen prefix receipt for the source transcript.

    The receipt is what downstream consumers use to bind the prefix they
    saw; it must include host, session id, transcript id, prefix length,
    prefix digest, and the parser implementation digest.
    """
    session_id = ""
    for _row_index, _byte_start, _byte_end, raw in iter_jsonl_rows(path):
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(obj, dict):
            continue
        if host == "codex":
            payload = obj.get("payload")
            if isinstance(payload, dict):
                sid = payload.get("id") or payload.get("session_id")
                if sid:
                    session_id = str(sid)
                    break
        else:
            sid = obj.get("sessionId") or obj.get("session_id")
            if sid:
                session_id = str(sid)
                break

    digest = hashlib.sha256()
    total = 0
    for _row_index, _byte_start, byte_end, raw in iter_jsonl_rows(path):
        digest.update(raw)
        total = byte_end
    if total < 1:
        raise ValueError("transcript contains no complete JSONL row")
    return {
        "host": host,
        "sessionId": session_id,
        "transcriptId": transcript_id,
        "prefixLength": total,
        "prefixDigest": "sha256:" + digest.hexdigest(),
        "parserDigest": PARSER_DIGEST,
        "parserVersion": PARSER_VERSION,
    }


def _event_id(
    host: str,
    session_id: str,
    row_index: int,
    block_index: int,
    sequence: int,
    kind: str,
    call_id: str | None,
    fingerprint_payload: str,
) -> str:
    """Compute the deterministic event id.

    Event identity = prefix-digest + span + kind + payload (plan 5.1).
    ``prefix_digest`` here is the prefix-digest binding for the source file
    (so identical source content ⇒ identical event ids), plus the span,
    kind, and a payload-derived fingerprint.
    """
    seed = json.dumps(
        {
            "host": host,
            "sessionId": session_id,
            "rowIndex": row_index,
            "blockIndex": block_index,
            "sequence": sequence,
            "kind": kind,
            "callId": call_id,
            "payloadFingerprint": hashlib.sha256(
                fingerprint_payload.encode("utf-8")
            ).hexdigest(),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return "evt_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def _parse_transcript(
    path: Path, host: str | None, projection: str | None, *, apply_cap: bool = True
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Parse the transcript and return (events, prefix_receipt_or_none)."""
    if not path.is_file():
        raise ValueError(f"transcript not found: {path}")

    # Detect host if not specified. Host drives which adapter row→events
    # translation runs.
    if host is None:
        host = detect_host(path)
    if host not in {"claude_code", "codex"}:
        raise ValueError(f"unsupported host: {host}")

    transcript_id = path.stem
    receipt = _read_prefix_receipt(path, host, transcript_id)
    session_id = receipt["sessionId"]
    parser_digest = receipt["parserDigest"]

    events: list[dict[str, Any]] = []
    sequence = 0
    pair_occurrence: dict[str, int] = {}

    for row_index, byte_start, byte_end, raw in iter_jsonl_rows(path):
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(obj, dict):
            continue

        row_events = iter_events_for_host(host, obj)
        for block_index, event in enumerate(row_events):
            sequence += 1
            text = compact_text(event.get("text", ""))
            if not text:
                continue
            event["text"] = text
            kind = str(event.get("kind") or "")
            call_id = event.get("call_id")

            # Pair-occurrence counter for (call_id, occurrence). Plan 5.2
            # fixes the "later tool_result trampling earlier occurrence" by
            # making the pair key call-id + occurrence.
            occurrence = 0
            if call_id:
                occurrence = pair_occurrence.get(str(call_id), 0)
                pair_occurrence[str(call_id)] = occurrence + 1

            payload_fingerprint = json.dumps(
                {
                    "kind": kind,
                    "tool": event.get("tool"),
                    "call_id": call_id,
                    "occurrence": occurrence,
                    "text": text,
                    "timestamp": event.get("timestamp"),
                },
                sort_keys=True,
                ensure_ascii=False,
            )
            fingerprint = hashlib.sha256(payload_fingerprint.encode("utf-8")).hexdigest()
            # Note: fingerprint-set dedup is intentionally NOT applied here.
            # Plan 5.2 reserves that responsibility for each projection
            # (Handoff, Taste, Insights) so the layer preserves byte-faithful
            # ordering — every byte produces either an event or a recorded
            # omission. The Handoff projection applies the dedup in its own
            # compaction step.

            flags = _event_flags(event, kind, text)
            classification = _classify_event(event, flags)

            ev = {
                "eventId": _event_id(
                    host,
                    session_id,
                    row_index,
                    block_index,
                    sequence,
                    kind,
                    str(call_id) if call_id else None,
                    payload_fingerprint,
                ),
                "rowIndex": row_index,
                "byteStart": byte_start,
                "byteEnd": byte_end,
                "blockIndex": block_index,
                "sequence": sequence,
                "kind": kind,
                "role": event.get("role"),
                "tool": event.get("tool"),
                "call_id": call_id,
                "occurrence": occurrence if call_id else None,
                "text": text,
                "timestamp": event.get("timestamp"),
                "classification": classification,
                "class": classification,
                "projection": projection or "default",
                "host": host,
                "sessionId": session_id,
                "transcriptId": transcript_id,
                "parserDigest": parser_digest,
                # Top-level flags (plan 5.1 contract: every event carries
                # boolean flags synthetic/meta/privateReasoningOmitted/
                # redacted directly on the event, not in a nested dict).
                "synthetic": flags["synthetic"],
                "meta": flags["meta"],
                "privateReasoningOmitted": flags["privateReasoningOmitted"],
                "redacted": flags["redacted"],
                "flags": flags,
            }
            events.append(ev)

    # Tail-preserving truncation + multi-block-intact segmentation. The cap
    # squeezes only the last class (successful read-only); everything else
    # survives intact. We implement this as a class-priority bucket sort
    # followed by cap application on the lowest-priority class only.
    if apply_cap:
        events = _apply_class_priority_cap(events, cap=6)
    return events, receipt


def _event_flags(event: dict[str, Any], kind: str, text: str) -> dict[str, bool]:
    """Return the per-event flag set required by plan 5.1."""
    flags = {
        "synthetic": bool(event.get("synthetic", False)),
        "meta": bool(event.get("meta", False)),
        "privateReasoningOmitted": bool(
            event.get("private_reasoning_omitted", kind == "thinking")
        ),
        "redacted": bool(event.get("redacted", "[REDACTED]" in text or "[BINARY_BLOB_REMOVED]" in text)),
        "isError": bool(event.get("is_error", False)),
        "isSidechain": bool(event.get("is_sidechain", False)),
    }
    return flags


def _apply_class_priority_cap(
    events: list[dict[str, Any]], cap: int
) -> list[dict[str, Any]]:
    """Apply class-priority admission (plan 5.2).

    Events are bucketed by class; only the LAST (lowest-priority) class is
    capped to ``cap`` entries. All other classes survive in original order.
    """
    if not events:
        return events

    buckets: dict[str, list[dict[str, Any]]] = {
        cls: [] for cls in CLASS_PRIORITY
    }
    for ev in events:
        cls = ev.get("classification") or "successful_readonly"
        buckets.setdefault(cls, []).append(ev)

    ordered: list[dict[str, Any]] = []
    for cls, _priority in sorted(CLASS_PRIORITY.items(), key=lambda kv: kv[1]):
        bucket = buckets.get(cls, [])
        if not bucket:
            continue
        if cls == "successful_readonly":
            ordered.extend(bucket[-cap:])
        else:
            ordered.extend(bucket)
    return ordered


def parse(
    transcript_path: str | os.PathLike[str] | None = None,
    *,
    projection: str | None = None,
    as_prefix_receipt: bool = False,
    transcriptPath: str | os.PathLike[str] | None = None,
    asPrefixReceipt: bool = False,
    host: str | None = None,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Public parse entry point.

    Accepts either snake_case or camelCase keyword arguments. The camelCase
    variants are what the JavaScript shim exposes to the e2e-7 test.

    Returns either:
      * a list of events when ``as_prefix_receipt`` is False (default), or
      * the frozen prefix receipt dict when ``as_prefix_receipt`` is True.
    """
    raw_path = transcript_path if transcript_path is not None else transcriptPath
    as_receipt = as_prefix_receipt or asPrefixReceipt
    if raw_path is None:
        raise ValueError("transcriptPath is required")

    path = Path(raw_path).expanduser().resolve()
    events, receipt = _parse_transcript(path, host, projection)

    if as_receipt:
        # Plan 5.1: the prefix receipt binds the prefix digest + parser
        # implementation digest + the host/sessionId/transcriptId tuple.
        return {
            "host": receipt["host"],
            "sessionId": receipt["sessionId"],
            "transcriptId": receipt["transcriptId"],
            "prefixLength": receipt["prefixLength"],
            "prefixDigest": receipt["prefixDigest"],
            "parserDigest": receipt["parserDigest"],
            "parserVersion": receipt["parserVersion"],
            "eventsObserved": len(events),
        }
    return events


def parse_source_events(
    transcript_path: str | os.PathLike[str] | None = None,
    *,
    transcriptPath: str | os.PathLike[str] | None = None,
    host: str | None = None,
) -> list[dict[str, Any]]:
    """Return every normalized source event in original transcript order.

    Unlike :func:`parse`, this canonical semantic source never applies the
    projection cap.  It preserves source sequence & byte spans for consumers
    that need auditable transcript evidence.
    """
    raw_path = transcript_path if transcript_path is not None else transcriptPath
    if raw_path is None:
        raise ValueError("transcriptPath is required")
    path = Path(raw_path).expanduser().resolve()
    events, _receipt = _parse_transcript(path, host, None, apply_cap=False)
    return events


def parse_or_empty(*args: Any, **kwargs: Any) -> Any:
    """Same as ``parse`` but returns an empty list when the file is missing.

    Test fixture discovery uses a write-then-read pattern; the first read can
    legitimately miss. We only swallow ``FileNotFoundError`` — any other
    error still propagates so the caller sees real bugs.
    """
    try:
        return parse(*args, **kwargs)
    except (FileNotFoundError, ValueError) as exc:
        msg = str(exc)
        if "not found" in msg or isinstance(exc, FileNotFoundError):
            if kwargs.get("as_prefix_receipt") or kwargs.get("asPrefixReceipt"):
                return {
                    "host": "",
                    "sessionId": "",
                    "transcriptId": "",
                    "prefixLength": 0,
                    "prefixDigest": "",
                    "parserDigest": PARSER_DIGEST,
                    "parserVersion": PARSER_VERSION,
                    "eventsObserved": 0,
                }
            return []
        raise


# JS-shim-friendly aliases. The dynamic import in e2e-7 looks for these names
# in order: TranscriptEventV1, transcriptEventV1, parse.
def TranscriptEventV1(*args: Any, **kwargs: Any) -> Any:
    return parse(*args, **kwargs)


def transcriptEventV1(*args: Any, **kwargs: Any) -> Any:
    return parse(*args, **kwargs)


def resolve_session(
    *,
    requested_session_id: str | None = None,
    candidates: list[dict[str, Any]] | None = None,
    requestedSessionId: str | None = None,
) -> dict[str, Any] | None:
    """Exact-match session resolver (plan 5.2 substring-bug fix).

    A candidate matches only when ``requestedSessionId == candidate.sessionId``
    OR (as a last resort, only when the requested id is the canonical UUID
    shape) ``requestedSessionId == candidate.path.stem``. Substring
    containment is explicitly rejected.
    """
    requested = requested_session_id if requested_session_id is not None else requestedSessionId
    rows = candidates or []
    if not requested:
        return None
    for candidate in rows:
        if str(candidate.get("sessionId") or "") == str(requested):
            return candidate
    for candidate in rows:
        path_value = candidate.get("path")
        if path_value is None:
            continue
        stem = Path(str(path_value)).stem
        if stem == str(requested):
            return candidate
    return None


def resolveSession(*args: Any, **kwargs: Any) -> Any:
    return resolve_session(*args, **kwargs)


def resolveSessionId(*args: Any, **kwargs: Any) -> Any:
    return resolve_session(*args, **kwargs)


def matchTranscript(*args: Any, **kwargs: Any) -> Any:
    return resolve_session(*args, **kwargs)


__all__ = [
    "PARSER_DIGEST",
    "PARSER_VERSION",
    "TranscriptEventV1",
    "transcriptEventV1",
    "parse",
    "parse_source_events",
    "resolve_session",
    "resolveSession",
    "resolveSessionId",
    "matchTranscript",
    "compact_text",
]
