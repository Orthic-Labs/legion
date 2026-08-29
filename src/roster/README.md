# Legion roster

`roster/{sage,alchemist,oracle}.md` is Legion's sole source for authority identity,
authority boundary, trigger boundary, & abstract model tiers. `doctrine/covenant-seat.md`
remains source for Covenant seats; Covenant is not a roster role.

Roster files own identity, authority, and tier only. Detailed operating method lives in
delegated doctrine (`doctrine/{sage,alchemist,oracle}.md` and specialist skill references),
which must not recreate a second role identity.

`legion bind --write` projects this roster into Codex, Gemini CLI, & a low-fidelity
`AGENTS.md` context block. Those generated harness files are outputs: never edit them
directly. Claude Code is not generated — the plugin package is its install owner, so
`agents/{sage,alchemist,oracle}.md` is hand-maintained and must be kept in sync with this
roster by hand. `pnpm legion:check` verifies that the two agree.

Model policy is capability-tiered: `frontier-judgment`, `balanced-executor`, &
`mechanical-cheap`. A host resolves compatible provider/model IDs; roster source
never names a vendor model.
