# Website regression gotchas

Use this checklist for landing-page redesigns and Designer's follow-up qualitative review. These are ship gates,
not suggestions.

## Whole-page coverage

- Inventory every rendered region before judging. A redesigned homepage cannot inherit a pass for
  adjacent or supposedly unchanged regions.
- Capture both section centers and section boundaries. Measure unexplained vertical dead bands at
  the hero exit, between pinned scenes, and before the first light or contrasting surface.
- Review color cadence by viewport count. If multiple consecutive screens share one dark surface,
  explicitly justify that pacing or break it earlier.
- Audit at the user's reported viewport in addition to standard breakpoints. A full-page thumbnail
  can hide dead space, clipping, and one-word headline wraps.

## Meaning before styling

- A heading must name the actual set beneath it. Do not call unrelated product modes "outcomes" of
  one voice input. File transcription is a workflow selected by a file, not a voice outcome.
- Each example must preserve a one-to-one trigger-to-result relationship. Never place one spoken
  command above several unrelated actions in a way that implies they all follow from it.
- Product labels must distinguish input kinds such as `YOU SAY` and `YOU CHOOSE`.
- Verify every claim and state against shipped code or the product source of truth.

## Layout and conversion

- Separate canvas width from reading measure. Feature surfaces may use the wide canvas; prose keeps
  a readable character measure inside it.
- Test headline wrapping at 375, 414, 768, 1024, 1440, and the reported viewport. Reject orphaned
  single-word lines that displace the primary action without an intentional composition.
- A commercial card gets one primary conversion path. If the price is known, the checkout link
  names the product and price. Do not pair a vague pricing link with a competing buy button.
- Checkout is part of the brand surface. Verify the locked wordmark and body fonts after font
  loading, at desktop and mobile widths.

## Motion reality

- Motion code existing is not motion working. Prove visible state change with time samples and prove
  scroll-linked change at multiple scroll positions.
- A reduced-motion branch must remain compact and readable. It must not leave the dimensions of a
  long pinned scene around a static frame.
- If the user explicitly opts into motion, that preference must propagate to every motion scene in
  the session. Do not read the preference once and strand later components in reduced mode.
- A persistent object requires perceptual continuity across the handoff. Reusing a component in
  disconnected sections is not evidence of continuity by itself.
- Prefer transform and opacity for continuous movement. Verify the rendered transform changes; a
  GPU-friendly property that never updates is still a failure.

## Evidence required to pass

- Region inventory and interactive-element inventory.
- Boundary crops, full-page capture, and region crops after fonts are ready.
- Visible-motion samples, scroll-progress samples, and a reduced-motion capture.
- Region-by-lens table with no silent gaps.
- Exact checkout destination, displayed price, hover, focus, and brand-font verification.
- External vision review only after deterministic failures are fixed. A jury cannot replace direct
  inspection of the actual pixels.
