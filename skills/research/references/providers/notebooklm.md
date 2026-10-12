# NotebookLM provider and artifact route

NotebookLM is not a top-level skill and is not an evidence authority.

## Supported host route & current CLI boundary

The host capability is named `notebooklm` in the Research route registry. Stateful NotebookLM work
is supported only through a callable `notebooklm` host adapter actually exposed in the current
host's tool list. Use that adapter's published operations and explicit notebook/source identifiers;
do not invent CLI subcommands or assume shared active-notebook state. Confirm notebook, source set,
artifact type, format, and download destination before a supported mutation. Private,
highly-sensitive, or medical uploads still require the applicable per-run approval.

The installed `legion research` command does not perform NotebookLM search, notebook creation,
upload, generation, or download. It consumes host-opened source records. For evidence processing,
open the underlying source, locate the passage, and supply a record that passes current
`legion-research` validation as `--source-record <record.json>`. Preserve the actual opened-source
provider and URI; records whose provider is `notebooklm`, or whose content is a NotebookLM answer,
are lead-only and cannot enter the evidence ledger.

If the current host exposes no callable `notebooklm` adapter, keep the requested route and report
`unavailable` with the missing host capability. Do not claim to have checked status, listed
notebooks, uploaded sources, generated an artifact, or downloaded output. The retired Python
prototype adapter is not installed, and `engine/crates/legion-research/src/source.rs` defines source
concepts rather than a stateful NotebookLM adapter. Keep OAuth state and `NOTEBOOKLM_AUTH_JSON`
secret. NotebookLM remains internal to the Research router, not a public skill or activation command.
