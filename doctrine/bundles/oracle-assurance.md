# Oracle — assurance method bundle

**What this is:** the recovered method manual for Oracle's browser/app QA craft — how to stand up a
hidden QA browser, drive functional interaction, capture visual evidence, and report findings.
Recovered verbatim from git history — deleted at workspace commit `d810d827` (claimed "absorbed"
into the new agent definitions; it was not). Source:
`git show d810d827^:tools/skills/qa/references/manual.md` (242 lines). Loaded by: Oracle, when the
audit surface is a running app/UI and the check requires functional interaction or visual capture
rather than static code inspection.

**Read `doctrine/oracle.md` first.** This bundle is the craft underneath that constitution, not a
replacement for it. Where this manual's routing language conflicts with current doctrine, a
`> **Superseded:**` note marks the change inline; everything else is preserved as originally
written, including its own internal skill name (`qa`) and file paths from its era.

**S10 handoff override:** consume only a sealed independent packet with frozen acceptance IDs,
exact state, prior findings, effect receipts, checkpoints, scope, & evidence references. Preserve
findings; dismiss at first failed configured gate; never expand review scope. Close a mapped
finding only with fresh exact-state evidence after remediation. A candidate or implementer claim
is not closure; no material delta means return current verdict, never loop.

---

# QA

```text
MODE: EXECUTE
PRIMARY_DELIVERABLE: Bounded QA evidence for frozen app routes and criteria.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: runtime
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Frozen QA criteria produce passing evidence or an exact failing artifact.
```

Use this for app QA where the default must be hidden/background browser automation, not foreground native windows.

## The Split

There are two layers. Keep them separate.

### Project QA Contract

This is the safer MailRight-style foundation. Each app should own scripts like:

```text
scripts/qa-browser.ps1       # Windows: start hidden QA app, write URL + PID
scripts/qa-browser-stop.ps1  # Windows: stop only that recorded process tree
scripts/qa-browser.sh        # Mac/Linux equivalent
scripts/qa-browser-stop.sh   # Mac/Linux equivalent
```

The app contract should:

- Start the dev server hidden on a free `127.0.0.1` port.
- Enable deterministic QA mode with both an env var and `?qa=1`.
- Write `.cache/qa-browser/url.txt`.
- Write `.cache/qa-browser/pid.txt` or equivalent process metadata.
- Put mocks at the IPC/API boundary, not inside random components.
- Never enable mocks in production builds.
- Stop only the recorded QA server process tree.

This is the regression harness surface.

### Shared QA Tooling

This shared skill provides generic runners under:

```text
tools/skills/qa/scripts/
```

- `qa-functional.mjs`: functional hover/click/type/key/assert/screenshot actions.
- `qa-shot.mjs`: viewport screenshot convenience wrapper.
- `qa.mjs`: shared dependency-free engine used by both wrappers.

These runners use installed Chrome/Edge directly through headless flags and raw CDP. They do not use Playwright or Puppeteer.

This is the evidence and interaction tooling, not a replacement for the project contract.

> **Superseded:** `tools/skills/qa/scripts/` no longer exists (the `qa` skill was retired along
> with `dispatch`/`debugger`/`architect`). Confirm the current location of these runners — or their
> functional equivalent — before invoking them; this manual's shell examples below assume the
> scripts still exist somewhere reachable and should be re-pointed once found, or the gap should be
> named to Sage as J-1's follow-on content work rather than silently assumed working.

## Best Implementation For A New App

Add four project scripts:

```text
scripts/qa-browser.ps1
scripts/qa-browser-stop.ps1
scripts/qa-browser.sh
scripts/qa-browser-stop.sh
scripts/qa-functional.mjs
scripts/qa-shot.mjs
```

Recommended `package.json` commands:

Windows:

```json
{
  "scripts": {
    "qa:browser": "powershell -ExecutionPolicy Bypass -File scripts/qa-browser.ps1",
    "qa:browser:stop": "powershell -ExecutionPolicy Bypass -File scripts/qa-browser-stop.ps1",
    "qa:functional": "node scripts/qa-functional.mjs",
    "qa:shot": "node scripts/qa-shot.mjs"
  }
}
```

Mac/Linux:

```json
{
  "scripts": {
    "qa:browser": "bash scripts/qa-browser.sh",
    "qa:browser:stop": "bash scripts/qa-browser-stop.sh",
    "qa:functional": "node scripts/qa-functional.mjs",
    "qa:shot": "node scripts/qa-shot.mjs"
  }
}
```

Project wrappers can either call the shared runners directly or delegate to them:

Windows:

```powershell
qa-shot --url (Get-Content .cache\qa-browser\url.txt) --out .cache\qa-shots\app.png
```

```powershell
qa-functional --url (Get-Content .cache\qa-browser\url.txt) --actions .cache\qa-actions.json
```

Mac/Linux:

```bash
qa-shot --url "$(cat .cache/qa-browser/url.txt)" --out .cache/qa-shots/app.png
```

```bash
qa-functional --url "$(cat .cache/qa-browser/url.txt)" --actions .cache/qa-actions.json
```

## Functionality QA

Purpose: "Does the app work?"

Use hidden app QA:

- Start with `pnpm qa:browser`.
- Drive `http://127.0.0.1:<port>/?qa=1`.
- Click, type, hover, press keys, open menus, switch routes.
- Assert DOM state, ARIA labels/titles, cursor, console/network errors, and workflow outcomes.
- Verify real flows: compose opens, labels select, settings tabs switch, drawers close, dialogs trap focus.

Example actions:

```json
[
  { "type": "waitFor", "selector": "[aria-label='Settings']" },
  { "type": "hover", "selector": "[aria-label='Settings']" },
  { "type": "assertCursor", "selector": "[aria-label='Settings']", "cursor": "pointer" },
  { "type": "click", "selector": "[aria-label='Settings']" },
  { "type": "waitForText", "text": "Appearance" },
  { "type": "press", "key": "Escape" },
  { "type": "assertAriaLabel", "selector": "button[title='Close']", "label": "Close" }
]
```

Run:

Windows:

```powershell
qa-functional --url "http://127.0.0.1:3000/?qa=1" --actions ".cache/qa-actions.json"
```

Mac/Linux:

```bash
qa-functional --url "http://127.0.0.1:3000/?qa=1" --actions ".cache/qa-actions.json"
```

Supported actions:

- `waitFor`, `waitForText`
- `click`, `hover`, `type`, `press`
- `eval`
- `assertVisible`, `assertText`, `assertAriaLabel`, `assertCursor`, `assertStyle`
- `screenshot`
- `sleep`

## Visual QA

Purpose: "Does it look right?"

Use ViewRight-style capture:

- `--shot` captures only the app viewport: no desktop, wallpaper, other windows, or browser chrome.
- Capture default, hover, active, selected, focused, disabled, error, empty, loading, long-text, and scrolled states.
- Review screenshots with a design eye: contrast, spacing, visual hierarchy, alignment, overlap, density, theme fit, and polish.
- Use computed styles to verify exact cursor/color/spacing claims; screenshots are evidence, not the only oracle.

Run:

Windows:

```powershell
qa-shot --url "http://127.0.0.1:3000/?qa=1" --out ".cache/qa-shots/app.png"
```

Mac/Linux:

```bash
qa-shot --url "http://127.0.0.1:3000/?qa=1" --out ".cache/qa-shots/app.png"
```

Screenshot modes every app should support at the project wrapper level:

- `viewport`: whole app viewport.
- `selector`: app shell only, e.g. `#root` or `.app`.
- `clip`: exact region, e.g. sidebar or toolbar.
- `full-page`: only when explicitly needed.

The shared engine currently guarantees viewport screenshots. Add project-level selector/clip wrappers when the app has stable shell selectors.

## Native/Tauri Foreground QA

Opt in only when the issue genuinely requires native behavior:

- installer lifecycle
- file associations
- native file dialogs
- OS hotkeys
- audio/input devices
- WebView-only packaged bugs
- window frame, taskbar, tray, or foreground focus behavior

Do not default to desktop screenshots for app visual QA.

## Report Format

Lead with findings:

```markdown
## Findings
- P1: Settings left-nav hover has no visible state. Evidence: `.cache/qa-shots/settings-hover.png`.
- P2: Icon-only close button has no accessible label. Selector: `button.close`.

## Evidence
- `.cache/qa-browser/url.txt`
- `.cache/qa-shots/default.png`
- `.cache/qa-shots/settings-hover.png`
- `.cache/qa-actions.log`

## Verification
- `pnpm qa:browser`
- `pnpm qa:functional -- --actions .cache/qa-actions.json`
- `pnpm qa:shot -- --out .cache/qa-shots/default.png`
```

Do not say a UI is fine just because automation can click it. Functional QA proves mechanics; visual QA still requires screenshot review.

> **Superseded:** this manual's classification labels (P1/P2, "Findings") predate Oracle's current
> **pass / fail / unknown / not-applicable** classification (`doctrine/oracle.md` "No false clean").
> Use this report format's structure (Findings / Evidence / Verification) but classify each finding
> with Oracle's current four-state verdict, not a bare priority label — and remember the
> non-negotiable underneath it: missing evidence never becomes a pass, so an unrun `qa:functional`
> check is `unknown`, not a silent skip.

## Machine-State Boundary (added 2026-08-10 after the HeardRight route-contamination escape)

**Green tests plus clean source do not certify machine state.** A production defect
escaped an Oracle audit because the audit inspected final source and fresh test behavior
while the actual poison lived in persistent machine state outside the repo: an
intermediate test had written a fake `two/cpu_only` route into the app's real
`recognition-route.json` under the production app-data directory, and the shipped
build then loaded CPU instead of DML. Source passed; the machine was poisoned.
Neither layer could see it structurally: Oracle never diffed app-data, and Arcane maps
subprocess file writes to `effect: null` by design (a command string is not a path).

Therefore, when auditing any change whose tests can touch runtime-loaded state:

1. **Enumerate the state surface first.** Before judging tests, list every path the
   product reads at runtime outside the repo — app-data directories, config files,
   caches, registries, env-pointed dirs (`HR_APP_DATA_DIR` and kin). The product's
   own config-loading code is the authority for this list, not the test suite.
2. **Diff production state across the test run.** Mechanical: `legion state
   snapshot --path <app-data> --out before.json` before tests, `legion state
   verify --snapshot before.json` after — nonzero exit names every delta. ANY delta under a production path caused by
   a test run is a finding — `fail`, not a note — regardless of whether the final
   test code uses mocks. The contaminating test may no longer exist; its residue does.
3. **Isolation is proven, not read.** "The committed test uses a mock persister" is
   evidence about source, not about the machine. If the audit cannot observe the
   state surface (no snapshot exists, paths unknown), the verdict for state safety
   is `unknown` — never `pass` inferred from mock usage in final source.
4. **Treat synthetic entries in production logs/stores as boundary-breach evidence.**
   A calibration log or route store containing values only a test would produce
   (`one`, `two`, fixture ids) is proof a test crossed the boundary at some point,
   even if the current suite is clean.
