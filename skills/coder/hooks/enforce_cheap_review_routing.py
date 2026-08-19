"""RETIRED 2026-07-05 — do not re-register. the operator locked the no-external-model-API rule:
audit/cortex/seo/commit lens work runs on NATIVE Claude subagents; /coder is opt-in only.
This hook force-rerouted native review spawns onto the external api-worker path, which is the
exact behavior that hung runs on provider limits. Removed from ~/.claude/settings.json and
hooks-manifest.json; hooks.json in this dir is now [] so install.py registers nothing.
Kept only as history.

PreToolUse hook for the Agent tool — force read-only reviews onto cheap API models.

Blocks an Agent spawn ONLY when it is, with high confidence, a read-only
review/lens/audit pass on an expensive Claude model (sonnet/opus). Those belong
on the free/cheap api-worker batch (the /coder skill), not on a paid Claude
subagent. Implementation, synthesis, and the ship gate are never touched.

Precision over recall: fires only when the prompt BOTH names a review intent AND
explicitly declares itself read-only, and carries no edit/synthesis verb. An
ambiguous sonnet spawn is allowed — better to miss one lens than to break real
work. Every fire (and near-miss) is logged so the heuristic can be tuned.

Bypass: put [claude-review] in the prompt/description, or set CHEAP_REVIEW_SKIP=1.

Block protocol: PreToolUse hookSpecificOutput permissionDecision=deny.
"""
import datetime
import json
import os
import sys

AUDIT_LOG = os.path.expanduser("~/.claude/usage-data/cheap-review-routing-audit.jsonl")

# A review/lens/critique intent.
REVIEW_MARKERS = (
    "review", "audit", "lens", "critique", "second opinion", "assess",
    "evaluate", "red team", "red-team", "adversarial", "skeptic", "find bug",
    "code review", "inspect", "verdict",
)
# An explicit read-only declaration (this is what makes the block high-precision).
READONLY_MARKERS = (
    "read-only", "read only", "do not edit", "don't edit", "no edits",
    "do not write", "don't write", "no writes", "report only", "findings only",
    "without editing", "do not modify", "don't modify", "lens", "critique only",
)
# Real work or Claude-grade synthesis — never redirect these.
EDIT_MARKERS = (
    "implement", "patch", "apply the", "write the", "edit the", "refactor",
    "create the", "modify the file", "fix the", "build the", "commit",
    "write_file", "apply_patch", "make the change", "synthes", "final report",
    "decide", "reconcile", "merge the", "ship",
)

REASON = (
    "BLOCKED: this looks like a read-only review/lens on an expensive Claude model. "
    "Route it to the free/cheap API models instead — build a manifest and run:\n"
    "  py -3.11 skills/coder/scripts/api-worker.py --batch manifest.json --pool-size 4\n"
    "(see the /coder skill; use --fallback code for risky code lenses). "
    "If this genuinely must run on Claude, add [claude-review] to the prompt or set CHEAP_REVIEW_SKIP=1."
)


def log(decision: str, model: str, snippet: str) -> None:
    try:
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": datetime.datetime.now().isoformat(timespec="seconds"),
                "decision": decision,
                "model": model,
                "snippet": snippet[:200],
            }) + "\n")
    except Exception:
        pass


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    ti = payload.get("tool_input", {})
    model = str(ti.get("model", "")).lower()
    text = " ".join(str(ti.get(k, "")) for k in ("prompt", "description", "subagent_type")).lower()

    expensive = ("sonnet" in model) or ("opus" in model)
    if not expensive:
        return 0  # haiku / unset — not our target

    bypass = "[claude-review]" in text or os.environ.get("CHEAP_REVIEW_SKIP") == "1"
    has_review = any(m in text for m in REVIEW_MARKERS)
    has_readonly = any(m in text for m in READONLY_MARKERS)
    has_edit = any(m in text for m in EDIT_MARKERS)

    if has_review and has_readonly and not has_edit and not bypass:
        log("block", model, text)
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": REASON,
            }
        }))
        return 0

    # Near-miss telemetry: a review on an expensive model that we let through
    # (had an edit verb, was bypassed, or didn't declare read-only). Helps tune.
    if has_review and (has_readonly or has_edit or bypass):
        log("allow", model, text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
