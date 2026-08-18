"""quick-ask.py — ad-hoc Codex/Gemini CLI consultation with forced machine-minimal output.

Outside the council /jury-* skills, raw `codex exec` and `gemini` calls don't auto-prepend
the machine-minimal directive. This wrapper closes that gap. Use this — never call codex/gemini raw.

USAGE
-----
  python quick-ask.py < question.txt
  python quick-ask.py -i question.txt
  echo "..." | python quick-ask.py
  python quick-ask.py -i q.txt --only codex
  python quick-ask.py -i q.txt --only gemini --model gemini-2.5-flash
  python quick-ask.py -i q.txt --gemini-model gemini-2.5-pro    # override default flash

DEFAULTS
--------
  Codex CLI:  gpt-5.5
  Gemini CLI: gemini-2.5-flash  (per CLAUDE.md §3 — cheap tier default; pro only on request)

OUTPUT
------
Both jurors run in parallel. Output is two labeled blocks (CODEX / GEMINI). Each juror is
forced to machine-minimal format both directions: the wrapper prepends the directive,
and the juror prompt instructs structured key:value output (no prose).
"""
from __future__ import annotations
import argparse
import sys
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Reuse the council subprocess provider — same enforcement path as engine.py
sys.path.insert(0, str(Path(__file__).parent))
from providers.subprocess_cli import SubprocessProvider
from providers.base import ProviderError

# Read canonical directive from shared policy so review tooling never depends
# on an installed lifecycle-hook helper.
with (Path(__file__).resolve().parents[1] / "lib" / "policy.toml").open("rb") as policy_file:
    MACHINE_MINIMAL_DIRECTIVE = tomllib.load(policy_file)["machine_minimal"]["content"]


CODEX_CONFIG = {
    "command_template": ["codex", "exec", "--skip-git-repo-check", "-m", "{model}", "-"],
    "timeout_s": 240,
}

GEMINI_CONFIG = {
    "command_template": ["gemini", "-m", "{model}", "-y"],
    "timeout_s": 240,
}


def call_juror(name: str, provider: SubprocessProvider, model: str, prompt: str) -> tuple[str, str, float, str | None]:
    t0 = time.time()
    try:
        full = f"{MACHINE_MINIMAL_DIRECTIVE}\n\n---\n\n{prompt}"
        out = provider.call(model, system=MACHINE_MINIMAL_DIRECTIVE, user=prompt, max_tokens=2048)
        return name, out, time.time() - t0, None
    except ProviderError as e:
        return name, "", time.time() - t0, str(e)


def main():
    ap = argparse.ArgumentParser(description="Ad-hoc Codex/Gemini CLI consultation with forced machine-minimal output.")
    ap.add_argument("-i", "--input", help="Read question from file (default: stdin)")
    ap.add_argument("--only", choices=["codex", "gemini", "both"], default="both",
                    help="Run only one juror (default: both in parallel)")
    ap.add_argument("--codex-model", default="gpt-5.5", help="Codex model (default: gpt-5.5)")
    ap.add_argument("--gemini-model", default="gemini-2.5-flash",
                    help="Gemini model (default: gemini-2.5-flash — cheap tier per CLAUDE.md §3)")
    args = ap.parse_args()

    if args.input:
        question = Path(args.input).read_text(encoding="utf-8")
    else:
        question = sys.stdin.read()

    if not question.strip():
        print("ERROR: empty input", file=sys.stderr)
        sys.exit(1)

    jurors = []
    if args.only in ("codex", "both"):
        jurors.append(("codex", SubprocessProvider("codex", CODEX_CONFIG), args.codex_model))
    if args.only in ("gemini", "both"):
        jurors.append(("gemini", SubprocessProvider("gemini", GEMINI_CONFIG), args.gemini_model))

    results: list[tuple[str, str, float, str | None]] = []
    with ThreadPoolExecutor(max_workers=len(jurors)) as pool:
        futures = [pool.submit(call_juror, name, prov, model, question) for name, prov, model in jurors]
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r[0])
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
    from pyio import ensure_utf8_stdio
    ensure_utf8_stdio()
    for name, out, elapsed, err in results:
        print(f"\n========== {name.upper()} ({elapsed:.1f}s) ==========")
        if err:
            print(f"ERROR: {err}")
        else:
            print(out.strip())


if __name__ == "__main__":
    main()
