# Headless Visual QA Capture Protocol

Capture/interaction layer for `audit-visual` Phase 1. Use this for routine background visual QA. It must not foreground a native app window, steal focus, or depend on the user's visible desktop.

Preferred capture order:

1. **Local `/qa` skill and project QA harness.**
   - Load the `/qa` skill instructions first and use its configured browser command, normally the gstack `browse` binary (`$B goto`, `$B snapshot`, `$B screenshot`, `$B responsive`, `$B click`, `$B fill`).
   - Start the app's documented browser QA mode, such as `npm run qa`, `pnpm qa:browser`, or the project-specific script in `AGENTS.md`, `CLAUDE.md`, `README`, or `docs/QA.md`.
   - Use the QA URL it emits, usually `http://127.0.0.1:<port>/?qa=1` or a documented route.
   - QA mode should use deterministic mocks for visual states.
   - Capture only the web/app surface, not the OS chrome.
   - Use `skills/qa/scripts/qa-shot.mjs` for viewport screenshots and `skills/qa/scripts/qa-functional.mjs` for hover/click/type/key/assert flows.

2. **Shared headless Chrome/Edge runner.**
   - Launch installed Chrome/Edge through the `/qa` scripts against the QA URL or local dev URL.
   - Set a desktop/app viewport for Windows apps, for example 1440x900 or the app's documented default size.
   - Navigate directly to the relevant route/state.
   - Use viewport evidence by default. Use project-level selector/clip wrappers when the app provides stable root selectors.
   - If an app root selector exists, prefer it, for example `#root`, `[data-app-root]`, `main`, or the documented shell selector.
   - If no root selector exists, screenshot the browser viewport only. Do not capture the monitor or native window frame.
   - Do not add Playwright/Puppeteer for this default QA loop.

3. **Built-in Claude/Codex browser, hidden/in-app, when available.**
   - Open the QA URL in the built-in browser.
   - Keep the browser hidden/background when the host supports that.
   - Interact with the page to create hover, focus, selected, loading, error, empty, dialog, and success states.
   - Save screenshots of the rendered app surface or viewport.
   - Do not use a text DOM summary as a visual substitute.

4. **Native Tauri/WebView2 foreground QA only by explicit request.**
   - Use the project's pinned native dev script, not a bare native dev command.
   - For SampleApp-style Tauri apps, use the documented script such as `.\scripts\dev.ps1`.
   - Treat native QA as WebView2 parity/smoke testing, not the routine visual review loop.
   - If native screenshot tooling captures blank or stale WebView2 content, it is not acceptable evidence.

Required capture scope:

- **App surface only:** capture the root app container or browser viewport containing the app. Exclude OS title bars, taskbars, terminals, command prompts, desktop background, and unrelated windows.
- **Desktop-first for Windows apps:** do not use mobile viewports unless the user explicitly asks for responsive/mobile checks.
- **Stateful evidence:** capture the exact states being reviewed. For app UI this usually means default, empty, loading, error, selected/active, hover/focus, pressed/clicked, modal/settings, long-content, and success states.
- **Interaction evidence:** for every reviewed interactive control group, inspect hover, focus, active/selected, pressed/clicked, disabled/unavailable, and long-label/adjacent-control behavior when applicable. Screenshots are required for visually meaningful states; DOM/text evidence alone is not enough.
- **Artifacts:** save screenshots to a local evidence directory and report paths in the review.

Suggested generic `/qa` pattern:

```powershell
pnpm qa:browser
$url = Get-Content .cache\qa-browser\url.txt
node skills/qa/scripts/qa-shot.mjs --url $url --out .cache\qa-shots\current\app-default.png
node skills/qa/scripts/qa-functional.mjs --url $url --actions .cache\qa-actions.json
```

If the project provides a dedicated screenshot script, use that instead of improvising. For SampleApp, follow `docs/QA.md` and the project `AGENTS.md`: routine visual QA uses the headless Vite QA harness, not foreground Tauri/WebView2.
