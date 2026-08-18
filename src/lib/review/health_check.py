#!/usr/bin/env python
"""health_check.py — probe every configured jury model for reachability.

Answers "which models are actually reachable, and why not" mechanically
instead of by prose that goes stale. Enumerates every distinct
(provider, model) pair in models.yaml — including fallbacks — sends a
trivial 1-token prompt, and classifies each:

  ok           - returned text
  unreachable  - ProviderError with an HTTP status (404 = model not in
                 the provider's catalog; 401/403 = auth; 429/503/504 = quota/busy)
  no_key       - provider has no API key in env (can't test from here)
  error        - other failure

Exit code is nonzero when any model wired as a PRIMARY seat (not just a
fallback) is unreachable — that's the case that silently collapses a
panel to its fallbacks. Fallback-only failures warn but don't fail the
run.

Usage:
  python src/lib/review/health_check.py            # table
  python src/lib/review/health_check.py --json     # machine-readable
  python src/lib/review/health_check.py --primary-only
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from providers import build_provider, ProviderError  # noqa: E402

PROBE_SYSTEM = "Reply with the single character: ok"
PROBE_USER = "ok"


def enumerate_models(cfg: dict) -> dict[tuple[str, str], dict]:
    """Return {(provider, model): {"primary_seats": [...], "fallback_seats": [...]}}."""
    seen: dict[tuple[str, str], dict] = {}

    def note(provider: str, model: str, seat: str, is_primary: bool) -> None:
        key = (provider, model)
        rec = seen.setdefault(key, {"primary_seats": [], "fallback_seats": []})
        rec["primary_seats" if is_primary else "fallback_seats"].append(seat)

    for panel, panel_cfg in cfg.get("panels", {}).items():
        for juror in panel_cfg.get("jurors", []) or []:
            if not (isinstance(juror, dict) and juror.get("provider") and juror.get("model")):
                continue
            seat = f"panel:{panel}:{juror.get('id', '?')}"
            note(juror["provider"], juror["model"], seat, is_primary=True)
            for fallback in juror.get("fallbacks", []) or []:
                note(
                    fallback["provider"], fallback["model"], f"{seat}.fb",
                    is_primary=False,
                )

    # Shared anchors + every skill lineup. YAML has already expanded merge keys,
    # so iterating skills covers the technical/vision/content lineups.
    for skill, sc in cfg.get("skills", {}).items():
        for j in sc.get("jurors", []) or []:
            if not (isinstance(j, dict) and j.get("provider") and j.get("model")):
                continue
            seat = f"{skill}:{j.get('id', '?')}"
            note(j["provider"], j["model"], seat, is_primary=True)
            for fb in j.get("fallbacks", []) or []:
                note(fb["provider"], fb["model"], f"{seat}.fb", is_primary=False)
        for rule in sc.get("escalation", []) or []:
            if rule.get("provider") and rule.get("model"):
                note(rule["provider"], rule["model"], f"{skill}:escalation", is_primary=False)
    return seen


def classify(provider_name: str, model: str, providers_cfg: dict, provider_obj) -> dict:
    if provider_obj is None:
        return {"status": "no_provider", "detail": "provider not built (missing config)"}
    t0 = time.time()
    try:
        # Reasoning models (gpt-oss, MiniMax-M3, deepseek) spend tokens thinking
        # before any content; a tiny cap misreads them as dead ("empty content,
        # finish_reason=length"). Give them room — the probe answer is still tiny.
        raw = provider_obj.call(model, PROBE_SYSTEM, PROBE_USER, max_tokens=1024)
        return {"status": "ok", "detail": (raw or "").strip()[:40],
                "latency_ms": int((time.time() - t0) * 1000)}
    except ProviderError as e:
        code = getattr(e, "status", None)
        msg = str(e).lower()
        if "no key" in msg or "no api key" in msg:
            kind = "no_key"
        elif code == 404 or "not found" in msg or "does not exist" in msg or "unknown model" in msg:
            kind = "unreachable"  # model not in provider catalog
        elif code in (401, 403):
            kind = "auth"
        elif code in (429, 503, 504) or getattr(e, "is_quota", False):
            kind = "busy"  # quota/rate — transient, model exists
        else:
            kind = "error"
        return {"status": kind, "http": code, "detail": str(e)[:120],
                "latency_ms": int((time.time() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "detail": f"{type(e).__name__}: {str(e)[:120]}"}


def main() -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
    from pyio import ensure_utf8_stdio
    ensure_utf8_stdio()
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--primary-only", action="store_true",
                    help="only probe models wired as a primary seat")
    args = ap.parse_args()

    from config import load_models_config
    cfg = load_models_config()
    providers = {}
    for name, pc in cfg["providers"].items():
        try:
            providers[name] = build_provider(name, pc)
        except Exception:  # noqa: BLE001
            providers[name] = None

    models = enumerate_models(cfg)
    results = []
    for (provider_name, model), usage in sorted(models.items()):
        is_primary = bool(usage["primary_seats"])
        if args.primary_only and not is_primary:
            continue
        disabled = bool(cfg["providers"].get(provider_name, {}).get("disabled"))
        res = {"provider": provider_name, "model": model, "primary": is_primary,
               "disabled_provider": disabled,
               "primary_seats": usage["primary_seats"],
               "fallback_seats": usage["fallback_seats"]}
        res.update(classify(provider_name, model, cfg["providers"], providers.get(provider_name)))
        results.append(res)

    primary_broken = [r for r in results
                      if r["primary"] and r["status"] in ("unreachable", "auth", "error")]

    if args.json:
        print(json.dumps({"results": results,
                          "primary_broken": [f"{r['provider']}/{r['model']}" for r in primary_broken]},
                         indent=2))
    else:
        print(f"{'STATUS':12s} {'PROVIDER':9s} {'MODEL':46s} {'ROLE':8s} DETAIL")
        print("-" * 100)
        for r in results:
            role = "PRIMARY" if r["primary"] else "fallback"
            icon = {"ok": "✅", "unreachable": "⛔", "auth": "🔒", "busy": "🕓",
                    "no_key": "·", "error": "⚠️", "no_provider": "⚠️"}.get(r["status"], "?")
            print(f"{icon} {r['status']:10s} {r['provider']:9s} {r['model']:46s} {role:8s} "
                  f"{r.get('detail', '')[:44]}")
        if primary_broken:
            print("\n⛔ PRIMARY seats unreachable (panels silently collapse to fallbacks):")
            for r in primary_broken:
                print(f"   {r['provider']}/{r['model']} — seats: {', '.join(r['primary_seats'])}")
        no_key = {r["provider"] for r in results if r["status"] == "no_key"}
        if no_key:
            print(f"\n· providers with no key in this env (untested): {', '.join(sorted(no_key))}")

    sys.exit(1 if primary_broken else 0)


if __name__ == "__main__":
    main()
