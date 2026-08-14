# Browser Automation — Real Browser Rule

For ANY task that requires opening a URL, clicking an element, scraping a page, or screenshotting a website, route to one of these engines in this order:

## Tier 1 — Host-native browser tool

Use the host-native browser tool first when present:
- Codex: Browser Use plugin / in-app browser.
- Claude: available browser MCP/tooling in the session.

This is the default for local app QA, screenshots, navigation, click/type flows, and visual checks.

## Tier 2 — Real-browser / CDP harness when authenticated state matters

Use a real-browser/CDP harness when the task needs existing login state, cookies, downloads/uploads, complex browser extension behavior, or repeated site workflows.

Standalone `agent-browser` is machine-specific. On Windows it may be exposed through `D:\workspace\bin\agent-browser.cmd`; on Mac, prefer the Codex Browser plugin or a local project QA runner before falling back to a global browser binary. A stale `.agent-browser` state directory alone does not prove the CLI is usable.

Borrow Browser Harness patterns:
- Save successful site-specific flows as reusable domain notes instead of rediscovering selectors.
- Create small helper code only when repeated browser work needs it.
- Keep helper files editable and reviewable.
- Do not enable broad auto-learning/helper-writing on financial, medical, identity, or account-management pages without the operator's approval.

## Tier 3 — Playwright MCP / heavy snapshot tools as last resort

Useful when a specific tool is available and you genuinely need its screenshot/snapshot behavior. Avoid for iterative workflows when it returns large page snapshots every action.

## Daemon-version-mismatch fix (agent-browser only)

If `open` returns "Failed to read: connection attempt failed":

Windows:

```powershell
taskkill /F /IM agent-browser-win32-x64.exe
Remove-Item "$env:USERPROFILE\.agent-browser\default.port","$env:USERPROFILE\.agent-browser\default.pid","$env:USERPROFILE\.agent-browser\default.version","$env:USERPROFILE\.agent-browser\default.stream" -ErrorAction SilentlyContinue
```

Mac:

```bash
pkill -f agent-browser || true
rm -f ~/.agent-browser/default.port ~/.agent-browser/default.pid ~/.agent-browser/default.version ~/.agent-browser/default.stream
```

Then retry.
