# Designer visual evidence capture

Use this reference when a qualitative critique needs rendered pixels. For capture procedure,
follow the canonical [`audit-visual` capture protocol](../../audit-visual/references/visual-qa-capture.md)
and the project's QA contract. This file makes that procedure reachable from Designer; it does not
make Designer the owner of rendered-state coverage.

- Review only the exact surface and states in scope. Use the project's deterministic QA mode and
  client-provided browser/capture tools when available; capture the app surface, not desktop chrome.
- Keep routine capture hidden/headless when supported; do not foreground a native app, steal focus,
  or depend on the user's visible desktop.
- Capture the target state itself. A DOM summary, source inspection, or default screenshot cannot
  stand in for pixels of a visually meaningful interaction state.
- For qualitative critique, gather enough pixels to substantiate the specific visual findings.
  Freeze a complete route/viewport/state matrix and reconcile coverage only when the request asks
  for rendered-state enumeration, coverage, or regression evidence; route that work to
  `/audit-visual`.
- QA owns functional interaction execution. Designer may use QA-produced captures as evidence,
  while making no claim that capture alone proves functional behavior.
- If the target cannot be rendered, the host has no capture capability, or required pixels are
  unreadable, label visual findings `UNPROVEN`. Source/spec observations may be reported separately
  as review-only; do not issue a visual pass/fail verdict from text alone.
- Preserve artifact paths and the state they represent. Never imply that an overlay, screenshot,
  or user-visible browser state exists unless capture actually produced it.
