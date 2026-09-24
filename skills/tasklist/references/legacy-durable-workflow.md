# Tasklist Durable Workflow Compatibility

Legacy Tasklist Markdown validation was **not** retired: it ships in this bundle and stays live.
`legion script tasklist/validate-tasklist` routes any `.md` packet, or an invocation carrying
`--template-self-check`, `--write-receipt`, or `--verify-receipt`, to the bundled
legacy engine. Everything else routes to the current typed-packet
(`dispatch-validator`) engine. `examples/validated-tasklist.md` is a live worked example of the
legacy path, not a historical artifact — keep it passing against `legion script tasklist/validate-tasklist`.

Use [durable workflow](durable-workflow.md) for the current typed-packet path. Use this legacy path
only for an existing Markdown record or a caller that still passes the legacy flags; new durable
records should default to typed packets plus shared-engine receipts.
