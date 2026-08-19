# Brand Registry: Differentiation Ledger

The Phase 3 guard in `brand-identity` checks every new or revised brand against a per-project registry of that project's own ventures, kept by the consuming project (not shipped with this skill). If no registry exists yet for the project, create one using the template below before running the guard.

No sibling brand should share four or more of the seven axes unless the user explicitly wants a same-family system. When a brand identity is approved, update the project's registry. The registry is mutable memory, not a static reference.

## Axes

1. **Base theme:** light, dark, paper, night, vivid, neutral, high-contrast.
2. **Type category:** reading serif, grotesque, humanist sans, mono-forward, display, script/hand, slab.
3. **Accent family:** hue family and usage behavior.
4. **Composition system:** editorial, Swiss grid, deck, radial, spine, asymmetrical, dense utility, cinematic.
5. **Mark logic:** wordmark, symbol, monogram, seal, system mark, kinetic mark, no-logo identity.
6. **Asset language:** photography, illustration, iconography, pattern, texture, motion, UI-native.
7. **Voice signature:** plainspoken, editorial, precise, warm, provocative, ceremonial, technical, playful.

## Portfolio Snapshot

Keep one row per venture in the project's own registry file. Do not invent or assume rows here — this skill ships with no portfolio data; the registry starts empty for every new project and is populated only from real, approved brand work.

## Update Template

```markdown
| [Brand] | [Register] | [Base] | [Type category] | [Accent family] | [Composition system] | [Mark logic] | [Asset language] | [Voice signature] | [Signature mechanism / notes] |
```

## Guard Procedure

1. Read the project's registry before Phase 3.
2. Compare the candidate brand to every row across the seven axes.
3. If it shares four or more axes with any sibling, adjust the candidate and re-run.
4. After user approval, add or update the row.
