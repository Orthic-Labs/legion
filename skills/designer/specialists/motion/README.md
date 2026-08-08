# Motion Director

A Designer branch for agency-quality web & native motion.

Designer loads this branch only for motion work.

---

## What's here

```
motion/
├── GUIDE.md         # Workflow, hard rules, output contract
├── principles.md    # Philosophy — meaning, persistent objects, language, easing, tokens, architecture, choreography
├── patterns/        # Vocabulary + implementation reference (36 patterns, 8 category files)
│   ├── _index.md
│   ├── entrance.md
│   ├── exit.md
│   ├── spatial.md
│   ├── attention.md
│   ├── layout.md
│   ├── gesture.md
│   ├── state.md
│   └── continuous.md
├── stack.md         # The decision tree — which library to use when, with costs and gotchas
└── reviews.md       # The QA gate — 10 sections, motion-gate.json schema
```

Read in this order: `GUIDE.md` → `principles.md` → `stack.md` → relevant `patterns/<category>.md` → `reviews.md`.

---

## Producer/reviewer split

**This guide is producer bar** — it owns motion philosophy, language, tokens, architecture, choreography, patterns, libraries, & producer-side QA checklist.

**Reviewer bar lives in `tools/skills/audit-visual/references/motion-standards.md`** — it owns escalation triggers, remedial hierarchy, & findings format.

Both files share easing values from `principles.md` §6. Drift breaks the contract.

---

## Routing contract

Designer ship mode invokes this guide. Without:
- `artifacts/motion-plan.md` (motion language, persistent objects, scenes, patterns, engines, restraint test)
- `artifacts/motion-gate.json` (verdict: pass)

…Phase 1.5 fails. The build cannot advance.

Full contract: `docs/ARCHITECTURE-MOTION.md` §9.

---

## Maintenance

When you revise a file, keep the others in sync:

- Add a new easing to `principles.md` → check `reviews.md`; update `tools/skills/audit-visual/references/motion-standards.md` if it diverges.
- Add a new pattern to `patterns/<category>.md` → check the count in `_index.md`.
- Add a new library to `stack.md` → check `principles.md` budget rules still hold.

---

## License

Use freely. Attribution appreciated but not required.
