#!/usr/bin/env python3
"""Canonical workspace implementation of Membrane's untrusted-data contract.

Consumers receive a structured, hash-bound envelope whose content can only be treated as
data. Embedded attempts to close or replace the fence remain JSON string data and the
parser fails closed on policy, schema, source, or hash changes.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA_VERSION = 1
INSTRUCTION_POLICY = 'data_only'


def _normalize(content: str) -> str:
    return content.replace('\x00', '').replace('\r\n', '\n').replace('\r', '\n').strip()


def fence(content: str, *, source: str) -> tuple[str, str]:
    if not source.strip():
        raise ValueError('source is required for a Membrane data fence')
    normalized = _normalize(content)
    digest = hashlib.sha256(normalized.encode('utf-8')).hexdigest()
    envelope = {
        'schemaVersion': SCHEMA_VERSION,
        'instructionPolicy': INSTRUCTION_POLICY,
        'source': source,
        'content_sha256': digest,
        'content': normalized,
    }
    return json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(',', ':')), digest


def open_fence(serialized: str, *, expected_source: str | None = None) -> dict[str, Any]:
    try:
        envelope = json.loads(serialized)
    except json.JSONDecodeError as exc:
        raise ValueError('Membrane data fence is not valid JSON') from exc
    if not isinstance(envelope, dict):
        raise ValueError('Membrane data fence must be an object')
    if envelope.get('schemaVersion') != SCHEMA_VERSION:
        raise ValueError('unsupported Membrane data fence schema')
    if envelope.get('instructionPolicy') != INSTRUCTION_POLICY:
        raise ValueError('Membrane data fence policy is not data_only')
    source = envelope.get('source')
    if not isinstance(source, str) or not source:
        raise ValueError('Membrane data fence source is missing')
    if expected_source is not None and source != expected_source:
        raise ValueError('Membrane data fence source mismatch')
    content = envelope.get('content')
    if not isinstance(content, str):
        raise ValueError('Membrane data fence content is not text')
    digest = hashlib.sha256(content.encode('utf-8')).hexdigest()
    if envelope.get('content_sha256') != digest:
        raise ValueError('Membrane data fence content hash mismatch')
    return envelope
