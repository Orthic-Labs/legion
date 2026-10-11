# Tasklist Durable Workflow Compatibility

The legacy Markdown tasklist validator is not part of this package and has no native route.
`legion script tasklist/validate-tasklist` accepts only typed JSON packets: `--packet-type authority|worker`,
`--receipt-mode write|verify`, and an optional `--receipt-dir`. It writes or verifies
`<packet-stem>.receipt.json`. Passing a `.md` file, `--write-receipt`, `--verify-receipt`, or
`--template-self-check` is not supported.

`examples/validated-tasklist.md` is a format example only. Its Markdown structure and receipt
are not checked by any native route. Its route binding is checked with
`legion script dispatch/validate-route`.

Use [durable workflow](durable-workflow.md) for the typed-packet path. An existing Markdown
record can be read as a record, but it has no native verifier.
