#!/usr/bin/env python3
"""Shared canonical-JSON, safe-path, raw-artifact & language-contract readers for code SDK validators.

The Python and Rust code SDK accuracy validators load these definitions with
runpy; this file has no command-line entrypoint of its own.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

RECEIPT_FIELDS = ("schemaVersion", "receiptId", "requestId", "providerId", "planId", "policyId", "policy", "taskId", "state", "complete", "executable", "command", "cwd", "environmentNames", "sandbox", "processTree", "timing", "exitCode", "signal", "stdout", "stderr", "parser", "gaps")


def require(value, message):
    if not value:
        raise AssertionError(message)


def keys(value, fields):
    require(isinstance(value, dict) and set(value) == set(fields), "unexpected object fields")


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def same(actual, expected, message):
    require(encoded(actual) == encoded(expected), message)


def receipt_fields(receipt, owner_projection=False):
    """Validate exact SDK fields, including the source-owned denial projection."""
    owner = "audit-native-owner-admission-v1"
    projected = owner_projection and isinstance(receipt, dict) and isinstance(receipt.get("policy"), dict) and receipt["policy"].get("id") == owner
    keys(receipt, RECEIPT_FIELDS + (("executionPolicy", "executionPolicyIdentity") if projected else ()))
    if projected:
        policy = {"externalProcesses": "owner-admission-required", "admissionStatus": "unavailable", "effectiveMode": "deny-external"}
        identity = {"id": owner, "version": 1, "digest": digest(encoded(policy))}
        same(receipt["executionPolicy"], policy, "original owner-admission policy projection differs")
        same(receipt["executionPolicyIdentity"], identity, "original owner-admission identity projection differs")
        same(receipt["policy"], dict(identity, allowed=False, reason="native-owner-admission-unavailable"), "projected owner admission is not the original denial")
        require(receipt["policyId"] == owner, "projected owner-admission policy ID differs")


def parsed(data):
    def pairs(items):
        require(len(items) == len(dict(items)), "duplicate JSON field")
        return dict(items)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "non-JSON number"))


def source_file(root, relative):
    path = PurePosixPath(relative)
    require(not path.is_absolute() and str(path) == relative and ".." not in path.parts and "\\" not in relative, "unsafe source path")
    actual = root
    for part in path.parts:
        actual /= part
        require(not actual.is_symlink(), "source symlink refused")
    require(actual.is_file(), "source file missing: " + relative)
    return actual


def absolute(value):
    require(isinstance(value, str), "retained absolute path missing")
    require(not any(c in value for c in "\0\r\n"), "retained absolute path contains controls")
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts and not value.startswith("//"), "retained path noncanonical")
    return path


def artifact(stream, retained, scratch, live):
    if retained is None:
        require(stream is None, "absent raw artifact has a receipt")
        return b""
    keys(retained, ("path", "absolutePath", "digest", "bytes", "immutable", "rawBytes"))
    require(isinstance(retained["rawBytes"], list) and all(type(b) is int and 0 <= b <= 255 for b in retained["rawBytes"]), "raw bytes malformed")
    raw = bytes(retained["rawBytes"])
    path = PurePosixPath(retained["path"])
    require(not path.is_absolute() and str(path) == retained["path"] and all(p not in ("..", ".") for p in path.parts) and len(path.parts) > 0, "artifact relative path unsafe")
    require(retained["immutable"] is True and type(retained["bytes"]) is int and retained["bytes"] == len(raw)
            and retained["digest"] == digest(raw), "retained raw artifact differs")
    same(stream, {key: retained[key] for key in ("path", "digest", "bytes", "immutable")}, "SDK receipt/raw artifact linkage differs")
    full = absolute(retained["absolutePath"])
    require(full == scratch / "artifacts" / path, "original artifact root/path differs")
    if live:
        actual = Path(full)
        require(not actual.is_symlink() and actual.is_file() and actual.read_bytes() == raw, "live SDK raw artifact changed")
    return raw


def required_contract(root, provider):
    """Parse only the source-owned literal LanguageConfig; fail closed on new syntax."""
    name = provider.removeprefix("code.").replace("-", "_")
    source = source_file(root, "engine/crates/legion-audit/src/native_providers/code/" + name + ".rs").read_text()
    match = re.search(r"pub const CONFIG: LanguageConfig\s*=\s*LanguageConfig::new\((.*?)\);", source, re.S)
    require(match is not None, "source language contract syntax changed")
    tokens = re.findall(r'"(?:[^"\\]|\\.)*"|[\[\](),&]|[^\s\[\](),&]+', match[1])
    cursor = 0
    def value():
        nonlocal cursor
        require(cursor < len(tokens), "incomplete language contract")
        token = tokens[cursor]
        cursor += 1
        if token == "&":
            return value()
        if token in ("[", "("):
            end = "]" if token == "[" else ")"
            out = []
            while cursor < len(tokens) and tokens[cursor] != end:
                out.append(value())
                if tokens[cursor] == ",":
                    cursor += 1
                else:
                    require(tokens[cursor] == end, "language contract separator differs")
            require(cursor < len(tokens), "language contract unclosed")
            cursor += 1
            return out
        require(token.startswith('"'), "nonliteral language contract refused")
        return parsed(token)
    values = []
    while cursor < len(tokens):
        values.append(value())
        if cursor < len(tokens):
            require(tokens[cursor] == ",", "language contract argument separator differs")
            cursor += 1
    require(len(values) == 5, "language contract argument count differs")
    return {"tools": values[3], "extensions": values[1], "variants": values[2], "requiredContext": values[4],
            "coverageRequirement": "bounded SDK accuracy requires every declared tool/context & source-owned control; arbitrary-input, platform & variant completeness remains distinct"}
