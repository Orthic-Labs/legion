# Audit Visual — Rendered-state evidence method

PRIMARY_DELIVERABLE: Bounded rendered-state evidence & coverage findings for exact granted surfaces.
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: `visual.core` reconciles its frozen matrix or reports typed `UNPROVEN` coverage.

Audit Visual owns deterministic enumeration, capture, comparison, & coverage of rendered UI. It
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

`/audit-visual` is a thin entrypoint over `../../src/providers/visual-core.mjs` & shared frozen plan.

1. Write visual specification.
2. Run `node ../../tools/audit/audit-run.mjs <root> --visual-spec <visual-spec.json>`.
3. For runtime captures, also supply `--url`, `--surfaces`, & optional `--visual-baselines`.
4. Read frozen `plan.json` before `visual.json`; `visual.core` must be selected before execution.
5. Finalize through shared report & SARIF pipeline; do not emit an incompatible report shape.

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
