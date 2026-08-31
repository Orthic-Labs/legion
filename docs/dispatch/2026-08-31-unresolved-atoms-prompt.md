# Unresolved atom reconciliation

Raw operator request:

> Okay. Now 21 are unresolved. Yes? Now I need you to use sub-agents and look at them. 9 partial, 11 unknown, 1 missing.

Frozen source: `D:/Claude/legion-closure` at `8b022aa632f21aaa76f4625640b500dd9cdb4e74`.

Purpose: reassess all 21 open Legion atoms against operative production source. Determine whether each current `PARTIAL`, `UNKNOWN`, or `MISSING` implementation classification is supported, should change, or remains unresolved. Do not close atoms, edit canon/pending, run tests/builds/generators, inspect sibling lane output, or infer behavior from filenames/tests/docs alone.

Foundation evidence rule: inspect smallest production surface able to disprove current state. Every proven mechanism must name production file + symbol, live caller/consumer, relevant state/fallback, & safeguard/test when present. Tests support but never replace production reachability. `DELIVERED` candidate requires complete observable behavior through live consumer; uncertainty remains explicit. Verification, qualification, delivery, & evidence remain separate lifecycle dimensions.

Exact partition:

- `legion-runtime`: LEG-017 through LEG-027 inclusive (11 rows: 10 UNKNOWN + 1 MISSING).
- `governance-guard`: LEG-005, LEG-015, LEG-016, GRD-009, GRD-013 (5 rows: 4 PARTIAL + 1 UNKNOWN).
- `arcane`: ARC-001, ARC-002, ARC-005, ARC-006, ARC-009 (5 PARTIAL rows).

Each report must contain exactly its assigned atoms once in this table:

| Scope | Domain | Atom | Current product | Best observed | Recommended implementation | Material gap | Why / tradeoffs | Source evidence | Confidence |
|---|---|---|---|---|---|---|---|---|---|

Use atom field as `ID — observable behavior`. `Current product` must recommend implementation disposition (`retain PARTIAL`, `retain UNKNOWN`, `retain MISSING`, `candidate DELIVERED`, `change to PARTIAL`, or `change to MISSING`) plus evidence boundary. `Best observed` is current live mechanism or `No proven winner`; no donor comparison is in scope. `Material gap` is `Yes`, `No`, or `Unresolved`. Confidence: High/Medium/Low under Foundation protocol. End with requested/evaluated/unresolved/excluded counts & one adversarial self-review statement.
