# Headless Visual QA Capture Protocol

Capture/interaction layer for `audit-visual` step 3 (see `SKILL.md`). Use this for routine background visual QA of **web products only**. Desktop, Tauri, and other native apps are never captured through this protocol: they are QA'd headless against the real installed build with RightKit QA, as `kind = "visual"` scenarios, with no dev server, `?qa=1` route, browser mock, or `--url` to a dev server. Web capture is recorded as `web` evidence only. It must not foreground a native app window, steal focus, or depend on the user's visible desktop. Every capture runs as a `kind = "visual"` scenario (rightkit-qa 0.5.0 or later). Functional checks without screenshots belong to the `qa` skill, which defaults to `kind = "functional"`.

Preferred capture order:

1. **Web product: local `/qa` skill and project QA harness.** Web products only.
   - Load the `/qa` skill instructions first and use the browser capability the host provides for driving the page (navigate, snapshot, screenshot, click, fill). Send a flow's steps as one batch when the capability accepts one; use one call per step only when a step's result decides the next step. If the host provides none, this route is unavailable; go to the next route or report the captures as `UNPROVEN`.
   - Start the app's documented browser QA mode, such as `npm run qa`, `pnpm qa:browser`, or the project-specific script in `AGENTS.md`, `CLAUDE.md`, `README`, or the project's QA doc (for example `docs/QA.md`, a project-overlay file that may not exist).
   - Use the QA URL it emits, usually `http://127.0.0.1:<port>/?qa=1` or a documented route.
   - QA mode should use deterministic mocks for visual states.
   - Capture only the web/app surface, not the OS chrome.
   - Use `legion script qa/qa-shot` for viewport screenshots. Run each hover/click/type/key/assert flow as one `legion script qa/qa-functional` call with its complete actions file, not one call per step.

2. **Web product: shared headless Chrome/Edge runner.** Web products only.
   - Launch installed Chrome/Edge through the `/qa` scripts against the web product's QA URL.
   - Set a desktop browser viewport for a web app, for example 1440x900 or the app's documented default size.
   - Navigate directly to the relevant route/state.
   - Use viewport evidence by default. Use project-level selector/clip wrappers when the app provides stable root selectors.
   - If an app root selector exists, prefer it, for example `#root`, `[data-app-root]`, `main`, or the documented shell selector.
   - If no root selector exists, screenshot the browser viewport only. Do not capture the monitor or native window frame.
   - Do not add Playwright/Puppeteer for this default QA loop.

3. **Web product: host built-in browser, hidden/in-app, when the host provides one.** Web products only.
   - Open the QA URL in the host's built-in browser.
   - Keep the browser hidden/background when the host supports that.
   - Interact with the page to create hover, focus, selected, loading, error, empty, dialog, and success states.
   - Save screenshots of the rendered app surface or viewport.
   - Do not use a text DOM summary as a visual substitute.

4. **Desktop, Tauri, and native apps: RightKit QA on the real installed build only.**
   - This is the only capture route for them. Run each visual flow as a `kind = "visual"` RightKit QA scenario against the installed build, using the `right-ctl` batch below.
   - Never start a dev server or native dev script, never open a `?qa=1` route, never capture a browser mock, and never pass `--url` to a dev server.
   - If RightKit QA cannot reach the installed build, record the captures as `UNPROVEN`. Do not substitute a dev-server route.
   - If native screenshot tooling captures blank or stale WebView2 content, it is not acceptable evidence.

**Batch by default.** For a RightKit app that exposes the control surface (`rightkit-qa-driver` 0.4.0 or later), send each visual flow as one `right-ctl run` JSON batch. This is the capture route for desktop, Tauri, and native apps. A flow without a `screenshot` step is functional and belongs to the `qa` skill. The `<app>.batch` tool runs up to 256 steps and stops at the first failure:

```sh
echo '[{"tool":"<app>.batch","args":{"steps":[
  {"method":"click","params":{"x":120,"y":40}},
  {"method":"type","params":{"text":"hello"}},
  {"method":"wait","params":{"js":"return !!document.querySelector(\"[data-state=done]\");","timeoutMs":5000}},
  {"method":"screenshot","params":{"inline":true}}]}}]' | right-ctl run
```

Use `wait` for each state the flow must reach. It waits in the page in one call and returns when the state appears, so do not add sleeps or repeated `eval` polls. Use one call per step only when a step's result decides the next step. Add `paceMs` to `click`, `drag`, `key` or `type` only when the page needs real time between events.

Required capture scope:

- **App surface only:** capture the root app container or browser viewport containing the app. Exclude OS title bars, taskbars, terminals, command prompts, desktop background, and unrelated windows.
- **Desktop-first for Windows apps:** do not use mobile viewports unless the user explicitly asks for responsive/mobile checks.
- **Stateful evidence:** capture the exact states being reviewed. For app UI this usually means default, empty, loading, error, selected/active, hover/focus, pressed/clicked, modal/settings, long-content, and success states.
- **Interaction evidence:** for every reviewed interactive control group, inspect hover, focus, active/selected, pressed/clicked, disabled/unavailable, and long-label/adjacent-control behavior when applicable. Screenshots are required for visually meaningful states; DOM/text evidence alone is not enough.
- **Artifacts:** save screenshots to a local evidence directory and report paths in the review.

Suggested generic `/qa` pattern (web products only; desktop and Tauri apps never use it):

Mac/Linux:

```bash
pnpm qa:browser
url="$(cat .cache/qa-browser/url.txt)"
legion script qa/qa-shot --url "$url" --out .cache/qa-shots/current/app-default.png
legion script qa/qa-functional --url "$url" --actions .cache/qa-actions.json
```

Windows example:

```powershell
pnpm qa:browser
$url = Get-Content .cache\qa-browser\url.txt
legion script qa/qa-shot --url $url --out .cache\qa-shots\current\app-default.png
legion script qa/qa-functional --url $url --actions .cache\qa-actions.json
```

If the project provides a dedicated screenshot script, use that instead of improvising. For a project that ships its own QA doc (SampleApp keeps `docs/QA.md`), follow it and the project `AGENTS.md`. A desktop or Tauri project's QA doc must route visual capture through RightKit QA on the installed build. A Vite or other web QA harness is `web` evidence only and never proves a desktop app.
