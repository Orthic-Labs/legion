"""Render the council result as a human-readable markdown verdict table."""
from __future__ import annotations

import re
from pathlib import Path


_TIER_PREFIX_RE = re.compile(r"^\s*\[(?P<tier>P0|P1|P2)\]\s*")

_LENSES_CACHE: dict | None = None


def _load_lenses() -> dict:
    """Load lenses.yaml keyed by lens name → lens_question (and full cfg).

    The renderer needs to look up `lens_question` from a juror's `lens`
    name so the headline answer (e.g. `intention_alternative_path`,
    `strongest_known_counterexample`) actually surfaces — engine.py writes
    the answer into `answers[lens_question]` but the rendered verdict
    previously only pulled `missing_evidence`. Without this, the lens is
    plumbing into a black hole.
    """
    global _LENSES_CACHE
    if _LENSES_CACHE is not None:
        return _LENSES_CACHE
    try:
        import yaml
        p = Path(__file__).parent / "lenses.yaml"
        _LENSES_CACHE = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        _LENSES_CACHE = {}
    return _LENSES_CACHE


def _lens_answer(juror: dict) -> str:
    """Pull the lens's headline answer from `answers[lens_question]`, if any.

    Returns empty string if the juror has no lens, no lens_question is
    registered for it, or no answer was emitted. Caller decides whether
    to render the empty string as `-`.
    """
    lens_name = juror.get("lens") or ""
    if not lens_name:
        return ""
    cfg = _load_lenses().get(lens_name) or {}
    q = cfg.get("lens_question") or ""
    if not q:
        return ""
    ans = (juror.get("answers") or {}).get(q) or ""
    return str(ans).strip()


def _tier_and_text(blocker) -> tuple[str, str]:
    """Normalize a blocker into (tier, text).

    Accepts dict {"tier": "P0", "text": "..."} (new shape), bare str
    (legacy), or "[P0] text" legacy prefix. Missing tier defaults to P1.
    """
    if isinstance(blocker, dict):
        tier = (blocker.get("tier") or "P1").upper()
        if tier not in {"P0", "P1", "P2"}:
            tier = "P1"
        return tier, str(blocker.get("text", "")).strip()
    text = str(blocker).strip()
    m = _TIER_PREFIX_RE.match(text)
    if m:
        return m.group("tier"), _TIER_PREFIX_RE.sub("", text).strip()
    return "P1", text


def _render_blockers_by_tier(all_jurors) -> list[str]:
    """Render the union of all jurors' blockers, grouped by tier.

    Locked policy 2026-07-14: P0 has no count or length cap (critical,
    ship-blocker). P1+P2 share a combined 8-cap at ≤200c each.
    """
    p0: list[str] = []
    p_rest: list[tuple[str, str, str]] = []  # (tier, juror, text)
    seen_text: set[str] = set()

    for j in all_jurors:
        juror = j.get("juror_id", "?")
        for blocker in j.get("blockers") or []:
            if not blocker:
                continue
            tier, text = _tier_and_text(blocker)
            if not text:
                continue
            key = text.lower()
            if key in seen_text:
                continue
            seen_text.add(key)
            if tier == "P0":
                p0.append(f"- {text} (from {juror})")
            else:
                p_rest.append((tier, juror, text))

    out: list[str] = []
    if p0:
        out.append(f"### Blockers — P0 (critical, ship-blocker; no count cap; n={len(p0)})")
        out.extend(p0)

    if p_rest:
        p_rest.sort(key=lambda t: (t[0], t[1]))
        cap = 8
        kept = p_rest[:cap]
        dropped = max(0, len(p_rest) - cap)
        out.append(
            f"### Blockers — P1+P2 (combined cap 8 at ≤200c each; {len(kept)} shown, {dropped} dropped)"
        )
        for tier, juror, text in kept:
            out.append(f"- [{tier}] {text} (from {juror})")
        if dropped:
            sample = all_jurors[0].get("juror_id", "?") if all_jurors else "?"
            out.append(f"_({dropped} more P1/P2 blockers suppressed by shared 8-cap; full list in {sample}.verdict.json)_")

    return out


def render(result: dict) -> str:
    out = []
    skill = result["skill"]
    syn = result["synthesis"]
    flags = result.get("flags") or {}

    # Packet validation (locked 2026-07-14)
    pv = result.get("packet_validation") or {}
    if pv:
        verdict = "✅ passed" if pv.get("ok") else "❌ failed"
        out.append(f"## Jury Verdict — `{skill}`  | packet: {verdict}")
        if pv.get("errors"):
            out.append(f"_packet errors ({len(pv['errors'])}):_")
            for e in pv["errors"][:5]:
                out.append(f"  - {e}")
        if pv.get("warnings"):
            out.append(f"_packet warnings ({len(pv['warnings'])}):_")
            for w in pv["warnings"][:5]:
                out.append(f"  - {w}")
        out.append("")
    else:
        out.append(f"## Jury Verdict — `{skill}`")
    if flags:
        flag_str = " ".join(f"`{k}={v}`" for k, v in flags.items())
        out.append(f"_flags: {flag_str}_\n")

    # Juror table — now with lens + lens_answer + missing_evidence columns.
    # Lens answer surfaces the per-lens headline (strongest_known_counterexample,
    # smallest_removable_slice, exploitable_or_unguarded_path,
    # intention_alternative_path) so the lens actually changes the verdict.
    # Without this column, lenses are plumbing into a black hole.
    out.append("| Juror | Lens | Provider/Model | Verdict | Score | Top concern | Lens answer | Evidence gap |")
    out.append("|---|---|---|---|---|---|---|---|")
    for j in result["jurors"]:
        verdict = j.get("verdict", "?")
        if j.get("degraded"):
            verdict += " ⚠"
        if j.get("fallback_used"):
            verdict += " ↩"
        if j.get("cache_hit"):
            verdict += " 💾"
        if not j.get("parsed_ok") and not j.get("cache_hit"):
            verdict = f"❌ {verdict}"
        model_short = j["model"].split("/")[-1][:40]
        lens = j.get("lens") or "-"
        missing = (j.get("answers") or {}).get("missing_evidence", "")
        if not missing:
            missing = ""
        missing_short = missing[:80] if missing else ""
        lens_ans = _lens_answer(j)
        lens_short = lens_ans[:80] if lens_ans else "-"
        out.append(
            f"| {j['juror_id']} | {lens} | {j['provider']}/{model_short} | "
            f"**{verdict}** | {j.get('score', 0)} | {(j.get('top_concern') or j.get('error') or '')[:80]} | "
            f"{lens_short} | {missing_short} |"
        )

    # Escalation
    if result.get("escalation"):
        out.append("\n### Escalation jurors")
        out.append("| Juror | Provider/Model | Verdict | Score | Top concern | Latency |")
        out.append("|---|---|---|---|---|---|")
        for j in result["escalation"]:
            verdict = j.get("verdict", "?")
            if not j.get("parsed_ok"):
                verdict = f"❌ {verdict}"
            model_short = j["model"].split("/")[-1][:40]
            out.append(
                f"| {j['juror_id']} | {j['provider']}/{model_short} | "
                f"**{verdict}** | {j.get('score', 0)} | {(j.get('top_concern') or j.get('error') or '')[:80]} | "
                f"{j.get('latency_ms', 0)}ms |"
            )

    # Synthesis line
    out.append("")
    out.append(f"### Majority: **{syn['majority_verdict']}** ({syn['majority_count']}) | Avg score: {syn['avg_score']}")
    notes = []
    if syn.get("split"):
        notes.append("⚠ split verdict")
    if syn.get("any_degraded"):
        notes.append("⚠ degraded juror used")
    if syn.get("any_error"):
        notes.append("❌ one or more jurors failed")
    if notes:
        out.append(" · ".join(notes))

    # Blockers, grouped by tier.
    all_jurors = result["jurors"] + result.get("escalation", [])
    blocker_lines = _render_blockers_by_tier(all_jurors)
    if blocker_lines:
        out.append("")
        out.extend(blocker_lines)

    out.append("\n_legend: ⚠=degraded ↩=fallback used 💾=cache hit ❌=error_")
    return "\n".join(out)
