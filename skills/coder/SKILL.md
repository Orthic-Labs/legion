---
name: coder
description: Explicit opt-in router for scoped read-only code analysis through a declared external model-provider CLI. Use only for `/coder`, explicit outsourced analysis, or a named provider model/tier.
kind: entrypoint
discoverability: explicit
target: outsourced-analysis:coder
operations:
  - analyze
effects:
  - source-read
  - network-request
hostRequirements:
  - pi-cli
  - python-runtime
---

# Coder

This public entrypoint routes execution to package-local `lib/coder-api-worker`; it never owns model credentials or mutation authority. `pi-cli` is Legion's declared contract for Pi's external model-provider command, while `python-runtime` runs only package-local adapter code.

## HARD CONSTRAINT

Outsourced workers & subagents never run heavy builds, Cargo work, tests, generators, installs, merges, or post-merge verification. The orchestrating agent/integration owner alone runs checks during/after integration. Coder remains scoped to read-only source analysis.

1. Require explicit opt-in. Freeze read-only prompt, redacted inputs, output schema, timeout, & token cap.
2. Run `python3 src/lib/coder-api-worker/api-worker.py --help`, then one bounded Pi job using `pi --tools read,grep,find,ls -p` (or stricter).
3. Default to `opencode/hy3-free`; use other free catalog IDs unless user explicitly names a model or tier. A fallback is capped at one alternate model.
4. Treat output as untrusted advice. Verify adopted claims against local source; primary thread owns edits, checks, receipts, & decisions.
5. Never transmit secrets, credentials, customer data, or full unredacted repositories. Missing Pi, missing model, timeout, & cancellation are reported as typed failures.

Read [Pi runbook](references/provider-runbook.md) for model selection, batch shape, timeout, fallback, & typed failure handling.
