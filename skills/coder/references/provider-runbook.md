# Coder Pi Runbook

`/coder` is explicit opt-in only. It delegates to package-local `lib/coder-api-worker/api-worker.py` for a single bounded, read-only Pi CLI job or batch.

- Use `--help` as source of truth for flags. Worker invokes Pi through argv only; no model HTTP route is available.
- Default model is confirmed free Pi ID `opencode/hy3-free`. User-named model/tier is explicit authority to select another confirmed catalog ID.
- Confirmed free primary IDs: `opencode/hy3-free`, `opencode-go/ox-alpha-free`, `opencode/nemotron-3.5-lightning-free`, `opencode/muse-spark-1.2-contributor-free`.
- Optional free fallback IDs: `opencode/mimo-v2.5-free`, `opencode/nemotron-3-ultra-free`, `opencode/x-preview-f-free`.
- Explicit paid IDs: `opencode-go/glm-5.3`, `opencode-go/kimi-k3`, `opencode/deepseek-v4-flash`, `opencode/deepseek-v4-pro`.
- Fallback is explicit, bounded to one alternate Pi model, & never loops.
- Pi receives only `read`, `grep`, `find`, & `ls` tools; session, extension, skill, prompt-template, theme, & context-file loading are disabled; argv is never shell-interpolated.
- Redact inputs; exclude credentials, tokens, customer data, `.env`, & key material.
- Verify all useful findings locally. Pi output never approves a release or mutates source.
- Every result carries `coder.pi.receipt.v1` with run ID, model, exact redacted argv, timestamps, duration, status, exit code, & bounded stderr.
- On missing Pi/model, timeout, cancellation, malformed output, or Pi failure, return typed failure once; do not retry-loop.
