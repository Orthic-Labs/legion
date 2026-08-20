# Legion shared-contract ID grammar

This package owns ID wire shapes. `docs/LEGION-CANONICAL-SSOT.md` owns architecture & semantic
ownership. IDs identify records; they never confer capability or authority.

## Human-facing sequence IDs

| Object | Regex | Example |
|---|---|---|
| Requirement | `^R-\d+$` | `R-2` |
| Decision | `^D-\d+$` | `D-17` |
| Invariant | `^I-\d+$` | `I-4` |
| Non-goal | `^NG-\d+$` | `NG-1` |
| Acceptance criterion | `^AC-\d+$` | `AC-8` |
| Execution contract | `^EC-\d+$` | `EC-44` |
| Execution task | `^T-\d+(\.\d+)*$` | `T-4.2` |
| Finding | `^F-\d+$` | `F-31` |
| Blocker | `^B-\d+$` | `B-5` |
| Amendment | `^A-\d+$` | `A-2` |
| Covenant advisory record | `^CV-\d+$` | `CV-7` |

`CV-` identifies challenge artifacts only. It does not place Covenant in authority roster or make
challenge evidence a release gate.

## Opaque runtime handles

Runtime handles use Crockford-base32 ULID suffixes:

| Handle | Regex |
|---|---|
| Run | `^run_[0-9A-HJKMNP-TV-Z]{26}$` |
| Request | `^req_[0-9A-HJKMNP-TV-Z]{26}$` |
| Runtime task | `^ktask_[0-9A-HJKMNP-TV-Z]{26}$` |
| Artifact | `^art_[0-9A-HJKMNP-TV-Z]{26}$` |
| Effect receipt | `^eff_[0-9A-HJKMNP-TV-Z]{26}$` |
| Evidence receipt | `^ev_[0-9A-HJKMNP-TV-Z]{26}$` |
| Claim | `^clm_[0-9A-HJKMNP-TV-Z]{26}$` |
| Worker capsule | `^wc_[0-9A-HJKMNP-TV-Z]{26}$` |

Content digests & source bindings use `^sha256:[0-9a-f]{64}$`.
