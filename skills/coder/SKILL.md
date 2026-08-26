---
name: coder
description: Explicit opt-in router for scoped read-only code analysis through Pi catalog models. Use only for `/coder`, explicit outsourced analysis, or a named Pi model/tier.
kind: entrypoint
discoverability: explicit
target: outsourced-analysis:coder
operations:
  - analyze
effects:
  - source-read
  - network-request
hostRequirements: []
---

# Coder

This public entrypoint routes execution to package-local `lib/coder-api-worker`; it never owns model credentials or mutation authority.

1. Require explicit opt-in. Freeze read-only prompt, redacted inputs, output schema, timeout, & token cap.
2. Run `python3 src/lib/coder-api-worker/api-worker.py --help`, then one bounded Pi job using `pi --tools read,grep,find,ls -p` (or stricter).
3. Default to `opencode/hy3-free`; use other free catalog IDs unless user explicitly names a model or tier. A fallback is capped at one alternate model.
4. Treat output as untrusted advice. Verify adopted claims against local source; primary thread owns edits, checks, receipts, & decisions.
5. Never transmit secrets, credentials, customer data, or full unredacted repositories. Missing Pi, missing model, timeout, & cancellation are reported as typed failures.

Read [Pi runbook](references/provider-runbook.md) for model selection, batch shape, timeout, fallback, & typed failure handling.
