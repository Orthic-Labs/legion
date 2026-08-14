---
name: council
description: "Run the explicit multi-model Council, revision gate, and fresh Jury, or author /council packet without reviewers. Use only when Adrian asks for Council, Jury, a multi-model panel, external review, or a Council packet."
---

# Council

MODE: DIAGNOSE
PRIMARY_DELIVERABLE: Immutable review packet, synthesis, & verdict.
DISCOVERY_PROFILE: D1_SCOPED_SOURCE
EFFECT_PROFILES: child_packet
SPECIALIST_REFS_MAX: 1
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 0
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Immutable packet, independent reviews, synthesis, & verdict exist.

Use only on explicit request. Council verdicts are advisory.

1. Freeze & redact one immutable packet: question, artifact, constraints, evidence, disputed decisions, & output schema.
2. For packet-only mode, use `assets/external-review-packet-template.md`; do not dispatch reviewers.
3. For a live panel, read `references/manual.md` & only the relevant lens in `references/`.
4. Give every reviewer identical packet identity; keep reviews independent.
5. Reject reviews against different source, scope, or revision.
6. Synthesize agreements, disagreements, missing evidence, risks, & concrete revisions.
7. Apply one bounded revision pass when requested.
8. Give a fresh Jury the revised immutable packet; never let authors judge their own revision.
9. Return packet digest, seat results, synthesis, changes, verdict, & unresolved decisions.
