# Native analysis packs

LEG-033 publishes eleven preclassified Class A lexical security packs as versioned,
executable-free data for the `analysis-rule-pack.v1` contract. Manifest order,
rule order, and classification rows are stable lexical orderings.

## Scope

- 11 Class A packs and 31 lexical rules are included.
- 0 Class B packs were present in the resolved ownership set.
- 29 Class C families remain excluded for named Rust provider packets.
- Rules retain stable IDs, source hashes, parity fixtures, lexical evidence,
  severity mapping, and uncertainty text.
- Rust-incompatible negative lookahead is represented by typed negative companion
  matchers; no callback, import, loop, or source expression is embedded.

## Provenance

- Baseline: `90678a130dc26937d544304b79a22f24d74383ac`
- Ownership digest: `bd4c842672618acd0df0fd93b8e1bd4b8f9048fb3f34f83232b7ea679ec0d812`
- Manifest SHA-256: `8249b1a99bf973c71cdd19336d10ff2681d970e8f1ef30be3aa387d33a06091a`
- Classification ledger SHA-256: `ac08c577b9d61c3ce420519406bb7431d50bdce8c8c032b71b2ff5576c5bac61`

`classification-ledger.v1.json` records each source hash, translated rule IDs,
parity fixture, destination hash, provenance, and later deletion path. Class C
exclusions and reasons are recorded there without translating their behavior.
