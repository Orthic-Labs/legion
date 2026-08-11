# NotebookLM provider and artifact route

NotebookLM is not a top-level skill and is not an evidence authority.

1. Check `notebooklm status` and `notebooklm list --json` before using the adapter.
2. Use explicit notebook IDs; do not rely on shared active-context state.
3. Private, highly-sensitive, or medical uploads require a per-run approval receipt.
4. An answer is stored as `evidence_status=lead`. Open its underlying source and locate the passage
   before creating an evidence record.
5. Confirm notebook, source set, artifact type, format, and download destination before mutations.
6. Keep OAuth state and `NOTEBOOKLM_AUTH_JSON` secret.

NotebookLM CLI usage belongs behind `tools/research-core/providers/notebooklm.py`. Provider help must
not reintroduce `/notebooklm`, `notebooklm` as a catalog skill name, skill install commands, or any
other public activation surface outside the root `research` router.
