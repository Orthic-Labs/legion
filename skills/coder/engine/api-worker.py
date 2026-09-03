#!/usr/bin/env python
"""Bounded, read-only Coder worker backed exclusively by the Pi CLI."""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import json
import re
import shutil
import subprocess
import sys
import time
import uuid
from typing import Any

PI_COMMAND = "pi"
PI_TOOLS = ("read", "grep", "find", "ls")
NO_THINK = "Return only a concise final answer; do not expose hidden reasoning."
READ_ONLY_DIRECTIVE = (
    "This is a read-only code-analysis job. Use only the supplied read-only Pi "
    "tools. Do not edit, write, delete, execute, or otherwise mutate files."
)

# Confirmed Pi catalog IDs. Keep this list source-local so callers cannot turn
# /coder into an arbitrary command or an accidental paid-model default.
FREE_PRIMARY_MODELS = (
    "opencode/hy3-free",
    "opencode-go/ox-alpha-free",
    "opencode/nemotron-3.5-lightning-free",
    "opencode/muse-spark-1.2-contributor-free",
)
FREE_FALLBACK_MODELS = (
    "opencode/mimo-v2.5-free",
    "opencode/nemotron-3-ultra-free",
    "opencode/x-preview-f-free",
)
PAID_MODELS = (
    "opencode-go/glm-5.3",
    "opencode-go/kimi-k3",
    "opencode/deepseek-v4-flash",
    "opencode/deepseek-v4-pro",
)
FREE_MODELS = FREE_PRIMARY_MODELS + FREE_FALLBACK_MODELS
MODEL_CATALOG = frozenset(FREE_MODELS + PAID_MODELS)

# A fallback is intentionally short: one alternate Pi model at most. This is
# bounded recovery, not a retry loop, and only happens when explicitly chosen.
FALLBACK_CHAINS = {
    "free": FREE_MODELS,
    "paid": PAID_MODELS,
    "bulk": FREE_MODELS,
    "code": FREE_MODELS,
    "fast": FREE_MODELS,
}
MAX_FALLBACK_ATTEMPTS = 2
MAX_POOL_SIZE = 8
MAX_PROMPT_CHARS = 120_000
MAX_OUTPUT_CHARS = 80_000
MAX_RECEIPT_TEXT_CHARS = 2_000
DEFAULT_TIMEOUT_SECONDS = 90
MAX_TIMEOUT_SECONDS = 600

# Reject obvious credential/key material before it reaches Pi. Generic words
# such as "token" are intentionally excluded to avoid blocking normal code.
SECRET_MARKERS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.I),
    re.compile(r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]", re.I),
    re.compile(r"(?:^|[\\/])\.env(?:$|[\\/])", re.I),
)


class WorkerFailure(Exception):
    """A typed, truthful preflight or Pi execution failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


def clip(value: str | None, limit: int = MAX_RECEIPT_TEXT_CHARS) -> str:
    value = value or ""
    return value if len(value) <= limit else value[:limit] + "…"


def strip_think(text: str) -> str:
    return re.sub(r"^\s*<think>.*?</think>\s*", "", text, flags=re.S).strip()


def read_input(path: str | None) -> str:
    if not path or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def validate_model(model: str) -> str:
    if model not in MODEL_CATALOG:
        raise WorkerFailure("model_unavailable", f"model is not in confirmed Pi catalog: {model}")
    return model


def validate_prompt(prompt: str) -> str:
    if not isinstance(prompt, str) or not prompt.strip():
        raise WorkerFailure("invalid_prompt", "a non-empty prompt is required")
    if len(prompt) > MAX_PROMPT_CHARS:
        raise WorkerFailure("prompt_too_large", f"prompt exceeds {MAX_PROMPT_CHARS} characters")
    for marker in SECRET_MARKERS:
        if marker.search(prompt):
            raise WorkerFailure("unsafe_input", "prompt appears to contain credentials or key material; redact it first")
    return prompt


def build_argv(model: str, prompt: str) -> list[str]:
    """Build argv without shell interpolation or mutation-capable tools."""
    validate_model(model)
    validate_prompt(prompt)
    return [
        PI_COMMAND,
        "--tools", ",".join(PI_TOOLS),
        "--no-session",
        "--no-extensions",
        "--no-skills",
        "--no-prompt-templates",
        "--no-themes",
        "--no-context-files",
        "--model", model,
        "-p", prompt,
    ]


def _receipt_base(run_id: str, model: str | None, argv: list[str] | None) -> dict[str, Any]:
    safe_argv = None
    if argv is not None:
        safe_argv = list(argv)
        if "-p" in safe_argv:
            index = safe_argv.index("-p") + 1
            if index < len(safe_argv):
                safe_argv[index] = "<prompt-redacted>"
    return {
        "schema": "coder.pi.receipt.v1",
        "run_id": run_id,
        "executor": "pi",
        "model": model,
        "tools": list(PI_TOOLS),
        "argv": safe_argv,
    }


def _finish_receipt(receipt: dict[str, Any], started_monotonic: float, started_at: str, *,
                    status: str, exit_code: int | None = None, stderr: str = "") -> dict[str, Any]:
    receipt.update({
        "started_at": started_at,
        "finished_at": utc_now(),
        "duration_ms": round((time.monotonic() - started_monotonic) * 1000),
        "status": status,
        "exit_code": exit_code,
    })
    if stderr:
        receipt["stderr"] = clip(stderr)
    return receipt


def _terminate(process: subprocess.Popen[str]) -> tuple[str, str]:
    try:
        process.terminate()
        stdout, stderr = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
    return stdout or "", stderr or ""


def run_pi(model: str, prompt: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Run exactly one bounded Pi invocation and return output plus receipt."""
    model = validate_model(model)
    prompt = validate_prompt(prompt)
    if not isinstance(timeout, int) or timeout < 1:
        raise WorkerFailure("invalid_timeout", "timeout must be a positive integer")
    timeout = min(timeout, MAX_TIMEOUT_SECONDS)
    argv = build_argv(model, prompt)
    run_id = uuid.uuid4().hex
    started_at = utc_now()
    started_monotonic = time.monotonic()
    receipt = _receipt_base(run_id, model, argv)

    if shutil.which(PI_COMMAND) is None:
        _finish_receipt(receipt, started_monotonic, started_at, status="pi_missing")
        return {"ok": False, "output": "", "error": {"code": "pi_missing", "message": "Pi CLI executable 'pi' was not found"}, "receipt": receipt}

    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", shell=False,
        )
        stdout, stderr = process.communicate(timeout=timeout)
    except FileNotFoundError:
        _finish_receipt(receipt, started_monotonic, started_at, status="pi_missing")
        return {"ok": False, "output": "", "error": {"code": "pi_missing", "message": "Pi CLI executable 'pi' was not found"}, "receipt": receipt}
    except subprocess.TimeoutExpired as exc:
        partial_out, partial_err = _terminate(process)
        partial_out = partial_out or (exc.output if isinstance(exc.output, str) else "")
        partial_err = partial_err or (exc.stderr if isinstance(exc.stderr, str) else "")
        _finish_receipt(receipt, started_monotonic, started_at, status="timeout", exit_code=process.returncode, stderr=partial_err)
        return {"ok": False, "output": clip(partial_out, MAX_OUTPUT_CHARS), "error": {"code": "timeout", "message": f"Pi exceeded {timeout}s timeout"}, "receipt": receipt}
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            _terminate(process)
        _finish_receipt(receipt, started_monotonic, started_at, status="cancelled")
        return {"ok": False, "output": "", "error": {"code": "cancelled", "message": "Pi job cancelled"}, "receipt": receipt}
    except OSError as exc:
        _finish_receipt(receipt, started_monotonic, started_at, status="launch_failed", stderr=str(exc))
        return {"ok": False, "output": "", "error": {"code": "launch_failed", "message": str(exc)}, "receipt": receipt}

    stdout = strip_think(stdout)
    status = "ok" if process.returncode == 0 and stdout else "failed"
    stderr = clip(stderr)
    if process.returncode != 0 and re.search(r"model|catalog|unknown.*model|not found", stderr, re.I):
        status = "model_unavailable"
    _finish_receipt(receipt, started_monotonic, started_at, status=status, exit_code=process.returncode, stderr=stderr)
    if status == "ok":
        return {"ok": True, "output": clip(stdout, MAX_OUTPUT_CHARS), "receipt": receipt}
    code = "model_unavailable" if status == "model_unavailable" else "pi_failed"
    message = stderr or f"Pi exited with status {process.returncode}"
    if not stdout and process.returncode == 0:
        code, message = "empty_output", "Pi returned no analysis output"
    return {"ok": False, "output": clip(stdout, MAX_OUTPUT_CHARS), "error": {"code": code, "message": message}, "receipt": receipt}


def _models_for_item(item: dict[str, Any]) -> tuple[str, ...]:
    if "provider" in item or "endpoint" in item or "api_key" in item:
        raise WorkerFailure("unsupported_route", "only Pi CLI execution is supported")
    if item.get("model") is not None:
        return (validate_model(str(item["model"])),)
    if item.get("tier") is not None:
        tier = str(item["tier"])
        if tier == "free":
            return (FREE_PRIMARY_MODELS[0],)
        if tier == "paid":
            return (PAID_MODELS[0],)
        raise WorkerFailure("invalid_tier", f"unknown Pi tier: {tier}")
    fallback = item.get("fallback")
    if fallback is not None:
        try:
            return tuple(FALLBACK_CHAINS[str(fallback)][:MAX_FALLBACK_ATTEMPTS])
        except KeyError as exc:
            raise WorkerFailure("invalid_fallback", f"unknown Pi fallback: {fallback}") from exc
    return (FREE_PRIMARY_MODELS[0],)


def _prepare_prompt(prompt: str, system: str = NO_THINK, max_tokens: int = 2048) -> str:
    max_tokens = max(128, min(int(max_tokens), 16_384))
    return validate_prompt(f"{READ_ONLY_DIRECTIVE}\n{system}\nKeep response within roughly {max_tokens} tokens.\n\n{prompt}")


def run_item(item: dict[str, Any]) -> dict[str, Any]:
    """Run one manifest item, with at most one explicitly requested fallback."""
    item_id = item.get("id")
    try:
        prompt = read_input(item.get("prompt_file")) if item.get("prompt_file") else item.get("prompt", "")
        prompt = _prepare_prompt(prompt, item.get("system", NO_THINK), item.get("max_tokens", 2048))
        models = _models_for_item(item)
        timeout = min(int(item.get("timeout", DEFAULT_TIMEOUT_SECONDS)), MAX_TIMEOUT_SECONDS)
        attempts: list[dict[str, Any]] = []
        for model in models:
            result = run_pi(model, prompt, timeout)
            attempts.append(result)
            if result["ok"]:
                result["id"] = item_id
                result["attempts"] = len(attempts)
                return result
        result = attempts[-1]
        result["id"] = item_id
        result["attempts"] = len(attempts)
        return result
    except WorkerFailure as exc:
        return {"id": item_id, "ok": False, "output": "", "error": {"code": exc.code, "message": exc.message}, "receipt": {"schema": "coder.pi.receipt.v1", "run_id": uuid.uuid4().hex, "executor": "pi", "status": exc.code, "tools": list(PI_TOOLS)}, "attempts": 0}
    except (OSError, ValueError, TypeError) as exc:
        return {"id": item_id, "ok": False, "output": "", "error": {"code": "invalid_job", "message": str(exc)}, "receipt": {"schema": "coder.pi.receipt.v1", "run_id": uuid.uuid4().hex, "executor": "pi", "status": "invalid_job", "tools": list(PI_TOOLS)}, "attempts": 0}


def run_batch(manifest_path: str, pool_size: int = 1) -> list[dict[str, Any]]:
    """Run manifest items with a bounded pool, preserving manifest order."""
    with open(manifest_path, "r", encoding="utf-8") as handle:
        items = json.load(handle)
    if not isinstance(items, list):
        raise WorkerFailure("invalid_manifest", "batch manifest must be a JSON array")
    pool_size = max(1, min(int(pool_size), MAX_POOL_SIZE))
    results: list[dict[str, Any] | None] = [None] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=pool_size) as pool:
        futures = {pool.submit(run_item, item): index for index, item in enumerate(items)}
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()
    return [result for result in results if result is not None]


def _single_output(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if result.get("ok"):
        print(result.get("output", ""))
    else:
        error = result.get("error", {})
        print(f"CODER_FAILURE [{error.get('code', 'unknown')}]: {error.get('message', '')}", file=sys.stderr)
    print("CODER_RECEIPT " + json.dumps(result.get("receipt", {}), ensure_ascii=False, sort_keys=True), file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded read-only code analysis through the Pi CLI")
    parser.add_argument("--model", help="Confirmed Pi catalog model ID")
    parser.add_argument("--tier", choices=("free", "paid"), default="free")
    parser.add_argument("--fallback", choices=sorted(FALLBACK_CHAINS), help="Use one bounded Pi model fallback")
    parser.add_argument("--batch", help="Manifest JSON array of Pi jobs")
    parser.add_argument("--pool-size", type=int, default=1)
    parser.add_argument("--input", help="Prompt file, or - for stdin")
    parser.add_argument("--system", default=NO_THINK)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--json", action="store_true", help="Emit structured result including receipt")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        assert strip_think("<think>noise</think>\nanswer") == "answer"
        assert build_argv(FREE_PRIMARY_MODELS[0], "review this")[:3] == ["pi", "--tools", "read,grep,find,ls"]
        assert all(model in MODEL_CATALOG for model in FREE_MODELS + PAID_MODELS)
        print("pi coder worker self-test passed")
        return 0

    if args.batch:
        try:
            results = run_batch(args.batch, args.pool_size)
        except (OSError, ValueError, WorkerFailure) as exc:
            print(json.dumps({"ok": False, "error": {"code": "invalid_manifest", "message": str(exc)}}))
            return 1
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0 if all(result.get("ok") for result in results) else 1

    try:
        prompt = _prepare_prompt(read_input(args.input), args.system, args.max_tokens)
        if args.model and args.fallback:
            raise WorkerFailure("ambiguous_selection", "use --model without --fallback")
        if args.model:
            models = (validate_model(args.model),)
        elif args.fallback:
            models = tuple(FALLBACK_CHAINS[args.fallback][:MAX_FALLBACK_ATTEMPTS])
        elif args.tier == "paid":
            models = (PAID_MODELS[0],)
        else:
            models = (FREE_PRIMARY_MODELS[0],)
        result: dict[str, Any] | None = None
        for model in models:
            result = run_pi(model, prompt, args.timeout)
            if result["ok"]:
                break
        assert result is not None
    except WorkerFailure as exc:
        result = {"ok": False, "output": "", "error": {"code": exc.code, "message": exc.message}, "receipt": {"schema": "coder.pi.receipt.v1", "run_id": uuid.uuid4().hex, "executor": "pi", "status": exc.code, "tools": list(PI_TOOLS)}, "attempts": 0}
    _single_output(result, args.json)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
