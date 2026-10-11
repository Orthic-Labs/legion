# Animation critique method

Use this reference when motion is present or requested for review. Designer owns qualitative motion
craft; deterministic rendered-state coverage belongs to `/audit-visual`, and functional interaction
behavior belongs to `/qa`.

1. Identify what the motion communicates or enables: spatial continuity, state change, feedback,
   explanation, or perceived wait. “Looks cool” alone is not a user purpose.
2. Review motion in context of the control and user task: timing, origin, interruption or reversal,
   repeated-use cost, hierarchy, consistency, and whether motion delays or obscures the next action.
3. Check applicable accessibility behavior: reduced-motion alternative, keyboard and focus continuity,
   screen-reader announcements for meaningful state changes, and absence of motion-only meaning.
4. Judge implementation evidence only against the matching platform guidance. Web and embedded
   WebView motion uses [`motion-standards.md`](motion-standards.md) plus the relevant
   [`motion specialist guidance`](../specialists/motion/GUIDE.md); native surfaces use
   [`native motion guidance`](../specialists/motion/native.md) and
   [`native-feedback.md`](native-feedback.md). Do not apply CSS, browser, or web timing rules to native UI.
5. Pair each motion finding with its UX purpose or consequence, name the observed motion/state,
   and give a proportionate correction. When code is in scope, show a concise before/after; do not
   claim performance, accessibility, or runtime behavior that was not observed or measured.

Load `../specialists/motion/GUIDE.md` and its platform branch for motion design or implementation. This
review reference does not replace those producer-side standards or prescribe one universal timing,
easing, or animation pattern.
