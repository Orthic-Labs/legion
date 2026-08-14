#!/usr/bin/env python
"""Tiny OpenAI-compatible read-only worker for /coder."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.request


PROVIDERS = {
    "nim": {
        "base_url": "https://integrate.api.nvidia.com/v1",
        "key_env": "NVIDIA_API_KEY",
        "model": "minimaxai/minimax-m3",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "key_env": "GROQ_API_KEY",
        "model": "qwen/qwen3.6-27b",
    },
    "cerebras": {
        "base_url": "https://api.cerebras.ai/v1",
        "key_env": "CEREBRAS_API_KEY",
        "model": "gpt-oss-120b",
    },
}

NO_THINK = "No hidden reasoning. No <think>. Return final answer only."

# NIM reasoning models HANG on non-streaming buffered reads and need the thinking
# kwarg disabled (else they emit endless traces / never return). Same fix as the
# jury engine — stream them and pass enable_thinking:false.
NIM_REASONING = {
    "deepseek-ai/deepseek-v4-pro",
    "nvidia/nemotron-3-super-120b-a12b",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning",
}
# Groq free tier caps tokens-per-minute (~8000, prompt+output combined); an 8192
# output request 413s. Cap Groq output so it fits under the wall.
GROQ_MAX_OUTPUT = 6000
# NIM free tier rejects CONCURRENT requests (504 on burst). Serialize all NIM calls
# across a batch; Groq/Cerebras still run concurrently.
_NIM_LOCK = threading.Lock()


def strip_think(text: str) -> str:
    return re.sub(r"^\s*<think>.*?</think>\s*", "", text, flags=re.S).strip()


def _read_stream(resp) -> str:
    """Accumulate SSE delta content from an OpenAI-compatible stream."""
    parts: list[str] = []
    for raw in resp:
        line = raw.decode("utf-8", "ignore").strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            break
        try:
            delta = json.loads(data)["choices"][0].get("delta") or {}
            if delta.get("content"):
                parts.append(delta["content"])
        except Exception:
            continue
    return "".join(parts)


def read_input(path: str | None) -> str:
    if not path or path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# Ordered provider/model fallback chains. First that answers wins; on a quota /
# transient error (429/5xx/timeout/URL) try the next. All members probed live
# 2026-06-23 (UA + UTF-8 fixes). Re-point here, not in every caller.
FALLBACK_CHAINS = {
    "bulk": [("nim", "minimaxai/minimax-m3"),
             ("nim", "nvidia/nemotron-3-super-120b-a12b")],
    "code": [("nim", "deepseek-ai/deepseek-v4-pro"),
             ("nim", "nvidia/nemotron-3-super-120b-a12b")],
    "fast": [("nim", "qwen/qwen3-next-80b-a3b-instruct"),
             ("nim", "minimaxai/minimax-m3")],
}

# HTTP codes worth retrying on the next chain member (vs failing fast on 400/401/403).
_RETRY_CODES = {408, 409, 429, 500, 502, 503, 504}


def call_one(provider: str, model: str | None, prompt: str, system: str = NO_THINK,
             max_tokens: int = 2048, temperature: float = 0.2, raw: bool = False,
             timeout: int = 90) -> str:
    """One OpenAI-compatible chat call. Raises urllib errors on failure."""
    cfg = PROVIDERS[provider]
    key = os.environ.get(cfg["key_env"])
    if not key:
        raise SystemExit(f"{cfg['key_env']} not set")
    model = model or cfg["model"]
    base_url = os.environ.get(cfg.get("base_env", ""), cfg["base_url"]).rstrip("/")
    # Groq's per-minute token wall: cap output so prompt+output fits.
    if provider == "groq":
        max_tokens = min(max_tokens, GROQ_MAX_OUTPUT)
    # NIM reasoning models must be streamed (else they hang) and need thinking off.
    stream = provider == "nim"
    if provider == "nim" and timeout < 120:
        timeout = 120
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if provider == "groq" and model == "qwen/qwen3.6-27b":
        payload["reasoning_effort"] = "none"
        payload["include_reasoning"] = False
    if provider == "nim" and model in NIM_REASONING:
        payload["chat_template_kwargs"] = {"enable_thinking": False}
    if stream:
        payload["stream"] = True
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if stream else "application/json",
            # Bare urllib's default UA (Python-urllib/x.y) is CF-WAF-banned
            # (error 1010) by some providers. A real UA passes, same as the jury.
            "User-Agent": "coder-api-worker/0.1 (https://github.com/operator)",
        },
        method="POST",
    )

    def _do() -> str:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if stream:
                return _read_stream(resp)
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"].get("content") or ""

    # Serialize NIM calls (free tier rejects concurrent requests); others run free.
    content = (_do() if not stream else _with_lock(_NIM_LOCK, _do))
    return content if raw else strip_think(content)


def _with_lock(lock: threading.Lock, fn):
    with lock:
        return fn()


def call_with_fallback(chain_name: str, prompt: str, system: str = NO_THINK,
                       max_tokens: int = 2048, timeout: int = 90) -> str:
    """Walk a FALLBACK_CHAINS entry; first member that answers wins."""
    chain = FALLBACK_CHAINS[chain_name]
    last_err: Exception | None = None
    for provider, model in chain:
        try:
            return call_one(provider, model, prompt, system, max_tokens, timeout=timeout)
        except urllib.error.HTTPError as exc:
            last_err = exc
            if exc.code not in _RETRY_CODES:
                raise  # 400/401/403 etc. are not transient — fail fast
            print(f"[api-worker] fallback: {provider}/{model} HTTP {exc.code} -> next",
                  file=sys.stderr)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_err = exc
            print(f"[api-worker] fallback: {provider}/{model} {exc} -> next", file=sys.stderr)
    raise SystemExit(f"all fallback members exhausted for '{chain_name}': {last_err}")


def _run_item(item: dict) -> dict:
    """One batch entry → {id, ok, output|error}."""
    try:
        prompt = read_input(item["prompt_file"]) if item.get("prompt_file") else item.get("prompt", "")
        system = item.get("system", NO_THINK)
        max_tok = int(item.get("max_tokens", 2048))
        if "fallback" in item:
            text = call_with_fallback(item["fallback"], prompt, system, max_tok)
        else:
            text = call_one(item["provider"], item.get("model"), prompt, system, max_tok)
        return {"id": item["id"], "ok": True, "output": text}
    except Exception as exc:  # noqa: BLE001 - report any failure per-item, don't abort the batch
        return {"id": item["id"], "ok": False, "error": str(exc)}


def run_batch(manifest_path: str, pool_size: int = 4) -> list[dict]:
    """Run a manifest of items concurrently; results in manifest order."""
    import concurrent.futures

    with open(manifest_path, "r", encoding="utf-8") as f:
        items = json.load(f)
    results: list[dict | None] = [None] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, pool_size)) as pool:
        futs = {pool.submit(_run_item, item): i for i, item in enumerate(items)}
        for fut in concurrent.futures.as_completed(futs):
            results[futs[fut]] = fut.result()
    return [r for r in results if r is not None]


def main() -> int:
    import pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "lib"))
    from pyio import ensure_utf8_stdio
    ensure_utf8_stdio()
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=sorted(PROVIDERS), default="groq")
    parser.add_argument("--model")
    parser.add_argument("--fallback", choices=sorted(FALLBACK_CHAINS),
                        help="Use a provider/model fallback chain instead of --provider/--model")
    parser.add_argument("--batch", help="Manifest JSON of items to run concurrently")
    parser.add_argument("--pool-size", type=int, default=4)
    parser.add_argument("--input", help="Prompt file, or - for stdin")
    parser.add_argument("--system", default=NO_THINK)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--raw", action="store_true", help="Do not strip leading <think> block")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        assert strip_think("<think>noise</think>\nanswer") == "answer"
        assert set(FALLBACK_CHAINS) == {"bulk", "code", "fast"}
        print("api-worker self-test passed")
        return 0

    # Batch mode: fan a manifest out concurrently, print one JSON array.
    if args.batch:
        results = run_batch(args.batch, args.pool_size)
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0 if all(r["ok"] for r in results) else 1

    try:
        if args.fallback:
            text = call_with_fallback(args.fallback, read_input(args.input), args.system,
                                      args.max_tokens)
        else:
            text = call_one(args.provider, args.model, read_input(args.input), args.system,
                            args.max_tokens, args.temperature, args.raw)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise SystemExit(f"HTTP {exc.code}: {body}")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
