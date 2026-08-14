---
name: audit
description: "Diagnose a whole repository through Legion's frozen Audit provider plan. Use for /audit or repository-wide read-only health, security, runtime, & evidence review."
metadata:
  legion:
    provenance: legion-authored-public-router
    licenseState: unresolved
    rightsReceipt: null
    publish: false
---

# Audit

Route only repository-wide diagnosis to Legion's shared Audit engine. This entrypoint owns no
provider registry, scanner, report format, or remediation loop.

1. For a whole-repository, read-only diagnosis, follow `../../SKILL.md` and run its canonical
   `audit-run.mjs` workflow.
2. Keep scope, revision, dirty state, provider plan, denominators, receipts, & degraded coverage
   bound to that run. Report `UNPROVEN` instead of inferring missing evidence.
3. Route a frozen report's bounded remediation to `/audit-fix`; rendered UI or screenshot review
   to `/audit-visual`; one frozen diff's review, commit, or push to `/commit`.

This package wrapper is unpublished: its source rights are unresolved & it has no rights receipt.
