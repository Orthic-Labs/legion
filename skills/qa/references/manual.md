# QA manual

## Scope

QA owns functional/behavioral QA, deterministic browser/runtime checks, tests-only authoring, mocks,
and viewport capture as supporting QA artifacts. This manual carries the recovered QA method (project QA contract,
shared runners, hidden-browser defaults, functional and rendered browser checks, report format, machine-state
boundary). It is **not** Oracle assurance, not Audit Visual's rendered-state audit, and not
Designer's qualitative craft.

## Test-only authoring

Use this branch when the requested result is a test for one named behavior, including a
regression test, edge-case test, property/fuzz test, invariant, trace assertion, performance
budget, or race check. It applies to native, backend, and web code; a browser is needed only when
the contract is observable only through browser behavior. Write tests only. Do not diagnose or
repair the implementation under test.

Before authoring, discover the target repository's actual test shape:

- Read the runner manifest/configuration and relevant CI invocation; report the command actually
  used rather than guessing from language or framework.
- Inspect a few nearby tests to match location, naming, fixtures/factories, mocks, and assertion
  style. Reuse existing fixtures and boundary seams.
- If no test infrastructure exists, state that fact and propose the smallest suitable addition;
  do not silently choose or install a framework.

Author against one named target at a time. If a test needs a product-code seam or refactor, report
the testability defect and route design to Architect. If evidence shows the behavior is wrong,
Debugger owns diagnosis and repair; this branch may provide the reproducing test as its starting
artifact.

Name the behavioral contract before writing assertions: observable failure modes, relevant
boundaries, and the input or state a careless implementation would mishandle. Reject a test that
only proves the target runs, and do not snapshot unreviewed current output. Keep each test focused
on one behavior. Coverage is a byproduct, not the contract.

Choose test shape from the failure mode; a unit test is a useful default, not a requirement. Use a
property test for a large input space, a fuzz seed/corpus for parser or input-driven crashes, an
invariant check for persistent or relational state, a trace assertion for a multi-step flow, a
performance budget only against a named repeatable baseline, and a race detector for concurrency
failures. Wire memory-safety checks to the repository's sanitizer or leak-check CI when applicable.
Use integration or browser assertions when the contract crosses those boundaries. Do not add every
shape or force a nondeterministic test where a reliable contract cannot be observed.

Where practical, run the test against broken or absent behavior first, retain the actual failing
assertion/output, then run it against the corrected or already-fixed behavior and retain actual
passing output. If red is impractical because the fix already shipped or needed infrastructure is
unavailable, say why and what would make the red run possible. Never claim red/green without both
observed results. A failed test may expose a testability seam or a product defect; leave product
repair to the user or `/debugger`.

For test-only authoring, report:

```text
TARGET:    <one named behavior>
RUNNER:    <discovered command>
LOCATION:  <test path, following repository convention>
CONTRACT:  <failure mode and relevant boundaries>
SHAPE:     <unit | integration | property | fuzz | invariant | trace | perf-budget | race | other>
RED:       <actual failure, or why it was not practical>
GREEN:     <actual pass, or not run with reason>
BOUNDARY:  <test only; product repair is outside this authoring task>
```

This report is for test-authoring tasks. Runtime QA keeps its existing acceptance, evidence,
reporting, and cleanup method below.

## The Split

There are two layers. Keep them separate.

### Project QA Contract

This is the safer SampleApp-style foundation. Each app should own scripts like:

```text
qa/browser.ps1       # Windows: start hidden QA app, write URL + PID
qa/browser-stop.ps1  # Windows: stop only that recorded process tree
qa/browser.sh        # Mac/Linux equivalent
qa/browser-stop.sh   # Mac/Linux equivalent
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

This shared skill provides two native runners, listed by `legion script --list`:

- `legion script qa/qa-functional --url <url> --actions <actions.json>`: functional hover/click/type/key/assert/screenshot actions.
- `legion script qa/qa-shot --url <url> --out <file.png>`: viewport screenshot (also `--sweep`).

They use installed Chrome/Edge directly through headless flags and raw CDP, and do not use Playwright
or Puppeteer. They are the Rust port `legion-runtime::wf_port::r54`; the former `qa.mjs`,
`qa-functional.mjs`, and `qa-shot.mjs` wrappers no longer exist, so a consuming app that shells out
must call `legion script ...` instead. `qa/browser.sh`, `qa/browser-stop.sh`, and their `.ps1`
equivalents are not package files — they are project scripts a consuming app authors itself.

## Best Implementation For A New App

Add four project scripts:

```text
qa/browser.ps1
qa/browser-stop.ps1
qa/browser.sh
qa/browser-stop.sh
```

Use `legion script qa/qa-functional` and `legion script qa/qa-shot` for the runners themselves (no equivalent project script needed).

Recommended `package.json` commands:

Windows:

```json
{
  "scripts": {
    "qa:browser": "powershell -ExecutionPolicy Bypass -File qa/browser.ps1",
    "qa:browser:stop": "powershell -ExecutionPolicy Bypass -File qa/browser-stop.ps1"
  }
}
```

Mac/Linux:

```json
{
  "scripts": {
    "qa:browser": "bash qa/browser.sh",
    "qa:browser:stop": "bash qa/browser-stop.sh"
  }
}
```

Project wrappers can either call the shared runners directly or delegate to them:

Windows:

```powershell
legion script qa/qa-shot --url (Get-Content .cache\qa-browser\url.txt) --out .cache\qa-shots\app.png
```

```powershell
legion script qa/qa-functional --url (Get-Content .cache\qa-browser\url.txt) --actions .cache\qa-actions.json
```

Mac/Linux:

```bash
legion script qa/qa-shot --url "$(cat .cache/qa-browser/url.txt)" --out .cache/qa-shots/app.png
```

```bash
legion script qa/qa-functional --url "$(cat .cache/qa-browser/url.txt)" --actions .cache/qa-actions.json
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
legion script qa/qa-functional --url "http://127.0.0.1:3000/?qa=1" --actions ".cache/qa-actions.json"
```

Mac/Linux:

```bash
legion script qa/qa-functional --url "http://127.0.0.1:3000/?qa=1" --actions ".cache/qa-actions.json"
```

Supported actions:

- `waitFor`, `waitForText`
- `click`, `hover`, `type`, `press`
- `eval`
- `assertVisible`, `assertText`, `assertAriaLabel`, `assertCursor`, `assertStyle`
- `screenshot`
- `sleep`

## Rendered browser checks

Purpose: prove declared functional, behavioral, browser, & runtime acceptance in rendered states.

Use SampleApp-style capture:

- `--shot` captures only the app viewport: no desktop, wallpaper, other windows, or browser chrome.
- Capture default, hover, active, selected, focused, disabled, error, empty, loading, long-text, and scrolled states.
- Assert only frozen observable criteria such as visibility, overlap, focus, state transition, exact computed style, viewport containment, or required text.
- Use computed styles to verify exact cursor/color/spacing acceptance; screenshots are supporting evidence, not a qualitative design oracle.
- Refer rendered-state enumeration, regression comparison, & evidence coverage to Audit Visual (named as the owner; QA does not invoke it).
- Refer subjective hierarchy, typography, spacing craft, density, theme fit, brand expression, & polish judgment or remediation to Designer (named as the owner; QA does not invoke it).

Run:

Windows:

```powershell
legion script qa/qa-shot --url "http://127.0.0.1:3000/?qa=1" --out ".cache/qa-shots/app.png"
```

Mac/Linux:

```bash
legion script qa/qa-shot --url "http://127.0.0.1:3000/?qa=1" --out ".cache/qa-shots/app.png"
```

Screenshot modes every app should support at the project wrapper level:

- `viewport`: whole app viewport.
- `selector`: app shell only, e.g. `#root` or `.app`.
- `clip`: exact region, e.g. sidebar or toolbar.
- `full-page`: only when explicitly needed.

The shared engine currently guarantees viewport screenshots. Add project-level selector/clip
wrappers when the app has stable shell selectors.

## Native/Tauri Foreground QA

Opt in only when the issue genuinely requires native behavior:

- installer lifecycle
- file associations
- native file dialogs
- OS hotkeys
- audio/input devices
- WebView-only packaged bugs
- window frame, taskbar, tray, or foreground focus behavior

Do not default to desktop screenshots for browser or native QA.

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
- `legion script qa/qa-functional --url "http://127.0.0.1:3000/?qa=1" --actions .cache/qa-actions.json`
- `legion script qa/qa-shot --url "http://127.0.0.1:3000/?qa=1" --out .cache/qa-shots/default.png`

## Skipped coverage
- List each frozen case not run, with the reason. Write `none` only when nothing was skipped.

## Cleanup
- `pnpm qa:browser:stop` (stops only the recorded QA server), then state what was removed or left running.
```

Do not say a UI satisfies frozen browser acceptance just because automation can click it. Assert each
required observable criterion or mark it unknown. Refer screenshot-matrix coverage & regression review
to Audit Visual, and qualitative judgment to Designer.

Classify each finding with the four-state verdict (`pass | fail | unknown | not-applicable`), not
a bare priority label. Missing evidence never becomes a pass: an unrun `qa/qa-functional` check is
`unknown`, not a silent skip.

## Machine-State Boundary (added 2026-08-10 after the SampleApp route-contamination escape)

**Green tests plus clean source do not certify machine state.** A production defect escaped an
audit because the audit inspected final source and fresh test behavior while the actual poison
lived in persistent machine state outside the repo: an intermediate test had written a fake
`two/cpu_only` route into the app's real `recognition-route.json` under the production app-data
directory, and the shipped build then loaded CPU instead of DML. Source passed; the machine was
poisoned. Neither layer could see it structurally: the audit never diffed app-data, and Arcane
maps subprocess file writes to `effect: null` by design (a command string is not a path).

Therefore, when QA/auditing any change whose tests can touch runtime-loaded state:

1. **Enumerate the state surface first.** Before judging tests, list every path the product reads
   at runtime outside the repo — app-data directories, config files, caches, registries,
   env-pointed dirs (`HR_APP_DATA_DIR` and kin). The product's own config-loading code is the
   authority for this list, not the test suite.
2. **Diff production state across the test run.** Mechanical: `legion state snapshot --path
   <app-data> --out before.json` before tests, `legion state verify --snapshot before.json`
   after — nonzero exit names every delta. ANY delta under a production path caused by a test run
   is a finding — `fail`, not a note — regardless of whether the final test code uses mocks. The
   contaminating test may no longer exist; its residue does.
3. **Isolation is proven, not read.** "The committed test uses a mock persister" is evidence about
   source, not about the machine. If QA cannot observe the state surface (no snapshot exists,
   paths unknown), the verdict for state safety is `unknown` — never `pass` inferred from mock
   usage in final source.
4. **Treat synthetic entries in production logs/stores as boundary-breach evidence.** A calibration
   log or route store containing values only a test would produce (`one`, `two`, fixture ids) is
   proof a test crossed the boundary at some point, even if the current suite is clean.

## Boundaries

- QA is not Oracle assurance: it produces evidence Oracle may consume, and does not certify
  completion.
- QA is not Audit Visual's rendered-state audit and not Designer's qualitative craft, though QA
  viewport captures serve both as evidence.
- Default to hidden browser QA. Use foreground/native work only for installer, file dialogs, OS
  hotkeys, devices, tray/window-frame, or packaged WebView behavior. Never capture desktop,
  wallpaper, another application, or browser chrome for routine QA.
