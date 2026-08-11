# Wave 1 rights/private-data audit

Source: `origin/main` at `6018132a92675eda2a1c8cbca0c6b1d3be223568`. Scope: **613 files** from 10 workspace skill roots, 4 source-command wrappers, and 6 current Legion/Nemesis manifests/registries.

## Result

Redistribution is not cleared for any file: {"blocked-private-data-review":157,"blocked-owner-supplied-nonstandard-license":5,"evidence-present-review-required":22,"blocked-license-evidence-missing":429}. Twenty-two files contain license-marker-like text, all remain review-required; owner-supplied manifest wording is recorded as evidence, not treated as a redistribution license.
Content classes: {"provider-integration":7,"generated-manifest-or-registry":6,"generic-engine":573,"private-overlay":19,"vendor-or-test-fixture":8}. Private-data signals: {"india":19,"legal":61,"medical":96,"private_identity":65,"private_venture":73}; signals require review and are not legal conclusions.

## Safe pilot sets

Internal-only pilot candidates by lens: Editorial **12/34**, Research **5/32**, Design **105/207**, Commercial **31/153**, SEO **9/94**, Brand **3/17**, Content **7/70**. Pilot status does not grant redistribution clearance.

## Hard blockers

| Lens | Blocker | Cutover disposition |
| --- | --- | --- |
| Editorial | Missing redistribution evidence; private/legal signals | Hold source-only; approve only reviewed generic candidates |
| Research | Medical/legal/India evidence & provenance gaps | Hold private routes; require source/provenance review |
| Design | Brand/private overlays & provider/vendor assets | Pilot generic engine only; retain overlays pending review |
| Commercial | Venture/private identity & owner terms | Hold commercial overlays; require owner terms |
| SEO | Missing license evidence & private claims | No public cutover until evidence review |
| Brand | Brand identity/private venture signals | Keep private; require explicit owner approval |
| Content | Provider/vendor/test fixtures & private signals | No redistribution; isolate reviewed internal pilot |

## Validation

Inventory completeness: **PASS** (613/613; missing=0; duplicates=0). Per-file SHA-256, byte count, line count, classification, evidence, blockers, disposition, and pilot status are present in `inventory.json`.
