---
name: content-demo-recorder
description: Route product walkthrough or cursor-driven macOS screen recording to local Demo tool.
---

# Demo recording

Runtime: `tools/demo/`. Read `tools/demo/AGENT-RUNBOOK.md`, then use `tools/demo/README.md` for current
CLI/schema details.

1. Run `node tools/demo/bin/demo.mjs doctor`.
2. Create or adapt a bounded version-1 scenario.
3. Dry-run scenario before foreground control.
4. Warn before real pointer, focus, or full-display capture.
5. Record no credentials, notifications, customer data, or private desktop content.
6. Inspect receipts, metadata, & final MP4; present MP4 for the operator's visual approval.

Keep demo recording separate from QA. Use local tool by default; request permission before paid or
cloud editing.
