# Audit Visual — Rendered-state evidence method

PRIMARY_DELIVERABLE: Bounded rendered-state evidence & coverage findings for exact granted surfaces.
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: qa (capture and interaction procedure only)
TERMINAL: `visual.core` reconciles its frozen matrix or reports typed `UNPROVEN` coverage.

Audit Visual owns deterministic enumeration, capture, & coverage of rendered UI. Native capture and
pixel comparison are bounded; an automatic runtime screenshot has no baseline binding and remains
review-required. It
does not own qualitative design taste, design-law critique, motion craft, typography direction,
composition, brand expression, or remediation; those belong to Designer. QA owns functional,
behavioral, browser, & runtime checks. Oracle may consume this evidence for independent assurance
but does not own this method.

## 1. Freeze scope before capture

Record one immutable visual specification containing:

- exact repository revision or artifact digest;
- routes, screens, components, & overlays in scope;
- viewports, themes, locales, platforms, & device-pixel ratios;
- required rendered states;
- baselines or explicit absence of baselines;
- stable-data/mocking requirements;
- acceptance criteria & permitted exclusions.

Each cartesian case receives a stable case ID. This matrix is coverage denominator. Missing cases
remain `UNPROVEN`; successful cases cannot average them away.

## 2. Capture protocol

For each case:

1. Establish exact URL, screen, viewport, theme, locale, platform, data fixture, & state.
2. Wait only on declared readiness signals; fixed sleeps are not readiness evidence.
3. Capture full surface plus region crops when density or length hides detail.
4. Record artifact path, digest, timestamp, runtime identity, & capture parameters.
5. Preserve failure artifacts for blank, loading-only, crashed, or unreachable states.

For live UI, QA may supply navigation & interaction evidence. Audit Visual consumes those results
without claiming ownership of functional success. Native surfaces require native capture tooling;
browser captures do not prove native pixels.

Required states are explicit, never inferred from one default screenshot. Typical states include:
default, hover, focus, pressed, selected, disabled, loading, empty, error, expanded, modal, & success.
Only states present in frozen matrix are mandatory for a given surface.

## 3. Inventory before comparison

Build two enumerations from frozen scope:

- `R1..Rn`: every rendered region, including floating elements, overlays, menus, & terminal states;
- `E1..En`: every stateful visible element required by matrix.

Map each capture to its regions/elements. Unmapped regions or elements are coverage defects. This
inventory is evidence topology, not qualitative critique.

## 4. Deterministic evidence checks

Apply only observable checks that can be reproduced from captured state:

- artifact exists, decodes, & matches declared dimensions;
- correct route/screen/state identity is visible;
- no blank, crash, loading-only, or wrong-target capture;
- required region/element is present;
- clipping, overlap, occlusion, overflow, truncation, missing asset, or raw placeholder is visible;
- expected viewport/theme/locale/platform cases exist;
- baseline comparison uses same normalized parameters;
- pixel or structural difference is measured & localized;
- repeated capture is stable within declared tolerance;
- accessibility scanner output is attached when supplied by QA/Audit, without treating absence as pass.

Do not convert subjective judgments such as “generic,” “weak hierarchy,” “poor typography,” or
“feels off” into Audit Visual findings. Route those to Designer with capture evidence attached.

## 5. Regression comparison

With `--visual-spec`, native visual compares declared capture PNGs with their declared baselines.
`--visual-baselines` freezes a digest-bound listing; a baseline name must resolve within that listing
and its bytes must still match. PNGs are fully decoded within fixed bounds & compared in RGBA space;
encoding metadata alone does not create a regression. Global `diff` options may set `channelThreshold`,
`maxChangedRatio`, & pixel `masks`; per-capture `diff` overrides global options. Invalid options,
dimensions, paths, or image decoding produce typed `UNPROVEN` results.

When runtime & visual are selected with `--url` and no explicit spec, runtime screenshots flow to visual
through the frozen plan's ordering-only capture source. Each screenshot is checked against its frozen
surface, viewport, plan-bound receipt, path, digest, byte length, & decoded dimensions. These screenshots
are supplemental captures without an inferred baseline; they always require review and cannot make the
visual result complete. The runtime provider remains incomplete. An explicit spec takes precedence and
runtime captures are never merged into its expected matrix or baseline map.

Baseline comparison requires matching revision identity, case parameters, rendering environment,
mask set, & tolerance policy. If any binding differs, classify comparison `UNPROVEN` unless frozen
spec explicitly permits normalization.

For each difference report:

- case ID & current/baseline digests;
- changed pixel/region bounds or structural locator;
- magnitude under declared metric;
- baseline binding;
- whether difference violates frozen acceptance criteria.

Audit Visual identifies regression evidence. Designer decides qualitative acceptability when frozen
criteria do not decide it. QA decides whether behavior causing a state is functionally correct.

## 6. Coverage reconciliation

Each matrix case ends in exactly one state:

- `PASS`: required artifact exists & all deterministic acceptance checks pass;
- `FINDING`: evidence shows a specific acceptance violation;
- `UNPROVEN`: capture, baseline, binding, tool, or readable evidence is missing;
- `NOT_APPLICABLE`: frozen spec explicitly excludes case, with reason.

Report totals against denominator. “No visual differences” is never a pass when matrix coverage is
incomplete. A full-page image does not prove hidden overlays or interaction states.

## 7. Shared provider execution

`/audit-visual` uses client-native capture tools plus Legion's shared frozen Audit plan.

1. For baseline comparison or a rich coverage matrix, freeze an explicit visual specification and run
   `legion audit <root> --visual-spec <file> [--visual-baselines <dir>] --out <run-dir>`.
2. For supplemental runtime captures without a baseline, select runtime & visual, provide `--url`, and
   omit `--visual-spec`; `--surfaces`, `--width`, & `--height` are frozen as runtime inputs.
3. Read `plan.json` before `visual.json`. Runtime-to-visual order is frozen without a success dependency,
   so partial runtime results can still contribute validated screenshots.
4. Finalize through shared report & SARIF pipeline; do not emit an incompatible report shape.

External vision review runs only when user explicitly requests it. Its output is advisory evidence,
must be checked against actual pixels, & never replaces matrix reconciliation.

## 8. Required output

Report:

- frozen subject/revision & visual-spec digest;
- matrix denominator plus `PASS/FINDING/UNPROVEN/NOT_APPLICABLE` totals;
- artifact index with paths, digests, & parameters;
- finding list with case ID, exact visible evidence, acceptance criterion, & baseline binding;
- region/element coverage table;
- unavailable tooling or unreadable evidence;
- referrals: qualitative craft → Designer, functional/runtime behavior → QA, repository-wide
  evaluation → Audit, independent completion judgment → Oracle.

Never prescribe or implement design remediation inside this method.
