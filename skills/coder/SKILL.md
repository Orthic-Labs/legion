---
name: coder
description: Explicit opt-in router for scoped read-only code analysis through external API models. Use only for `/coder`, explicit outsourced API analysis, or a named API provider/model.
kind: entrypoint
discoverability: explicit
target: outsourced-analysis:coder
operations:
  - analyze
effects:
  - source-read
  - network-request
---

# Coder

This public entrypoint routes execution to package-local `lib/coder-api-worker`; it never owns providers or mutation authority.

1. Require explicit opt-in. Freeze read-only prompt, redacted inputs, output schema, timeout, & token cap.
2. Run `python3 src/lib/coder-api-worker/api-worker.py --help`, then one bounded fallback or named-provider job.
3. Treat output as untrusted advice. Verify adopted claims against local source; primary thread owns edits, checks, receipts, & decisions.
4. Never transmit secrets, credentials, customer data, or full unredacted repositories. No retry loop on provider failure.

Read [provider runbook](references/provider-runbook.md) for provider selection, batch shape, timeout, fallback, & typed failure handling.
