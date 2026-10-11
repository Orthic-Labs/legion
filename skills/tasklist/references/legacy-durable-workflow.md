# Tasklist Durable Workflow Compatibility

`legion script tasklist/validate-tasklist` defaults to typed JSON packets for governed work:
`--packet-type authority|worker`, `--receipt-mode write|verify`, and optional `--receipt-dir`.
It writes or verifies `<packet-stem>.receipt.json` only through the corresponding validator.

For historical tasklist Markdown, explicitly select `--packet-type legacy`. This rejects
unrecognized task format, clock gaps, incorrect durations, and invalid lane overlaps before
forwarding to existing dispatch validation. Passing timing checks alone is not a valid packet
or an authority receipt. Ordinary inline tasklists do not need this compatibility mode.

`examples/validated-tasklist.md` remains a historical format example, not proof that its old
receipt is valid today. Use [durable workflow](durable-workflow.md) for current typed packets;
route bindings have their own `legion script dispatch/validate-route` check.
