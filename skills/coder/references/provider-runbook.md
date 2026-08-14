# Coder Provider Runbook

`/coder` is explicit opt-in only. It delegates to `tools/lib/coder-api-worker/api-worker.py` for a single bounded, read-only worker job or batch.

- Use `--help` as source of truth for providers & flags.
- Prefer worker fallback selection unless user names a provider/model.
- Redact inputs; exclude credentials, tokens, customer data, `.env`, & key material.
- Verify all useful findings locally. Provider output never approves a release or mutates source.
- On timeout, rate limit, malformed output, or provider failure, return typed failure once; do not retry-loop.
