# Interface Craft Tests

Seven named tests for catching defaults masquerading as decisions. Run these during Phase 3 (Visual Craft) and Phase 4 (Interaction/Kinesthetics) of any non-trivial review.

## 1. Every Choice Must Be a Choice

For each major decision — layout structure, color temperature, typeface, spacing scale, hierarchy system — the reviewer must state WHY.

"It is common" / "it is clean" / "it works" = a default, not a choice.

A choice requires a product-specific reason: what does THIS surface communicate, and why does this decision serve that communication better than the alternatives?

**How to apply:** list the 5–7 most salient decisions in the UI. For each, ask: could I defend this choice against a client who asks "why this one?" If the answer is "everyone does it" or "it looks nice," flag it.

## 2. Sameness Is Failure

If another AI given a similar brief would produce substantially the same output, the design failed.

Generic ≠ safe. Generic = forgettable.

**How to apply:** mentally substitute "a generic SaaS tool in this category" for the product. If the interface is indistinguishable from that substitute, name the three elements most responsible and demand they be made specific to the product.

## 3. The Swap Test

Take any design choice and swap it for the most common alternative. If nothing meaningfully changes for the user, that was a default.

Examples:
- Swap the primary blue for a warm amber. Does the product feel different? It should.
- Swap the rounded card for a square card. Does hierarchy or domain shift? If not, the radius was a default.
- Swap the sans-serif for a humanist serif. Does the voice change? It should reflect a choice about tone.

**How to apply:** run the swap test on: primary color, border radius, typeface class, spacing scale, and motion timing. Flag any swap that produces "eh, same vibe."

## 4. The Squint Test

Blur/defocus your view of the UI (literally squint or apply a Gaussian blur mentally). Ask:

- Is the hierarchy still perceivable? (Yes = good)
- Does anything harsh jump out? (No = good — craft whispers)
- Do the key action zones pull the eye? (Yes = good)

A good UI survives the squint test. A cluttered, noisy, or poorly-weighted UI reveals itself immediately.

## 5. The Signature Test

Name 5 concrete elements where this product's visual signature appears. A signature you cannot locate does not exist.

Signatures are specific: not "it uses blue" but "the primary action uses an ember glow on dark-coffee backgrounds." Not "it has animations" but "drawers enter with a gravity-weighted ease-in, not a spring."

**How to apply:** list the 5 signature elements. If you cannot name 5, the UI has a default visual identity, not a designed one. Blockers and major issues in that case.

## 6. The Token Test

Read the CSS custom properties / design tokens aloud. Do they evoke THIS product world, or any project?

Good: `--ink`, `--parchment`, `--ember`, `--coffee-dark`, `--signal-green`

Default: `--gray-700`, `--surface-2`, `--blue-500`, `--primary`, `--secondary`

Tokens are the vocabulary the UI speaks in. Generic vocabulary = generic product. If the tokens are generic, the product can never feel specific — the root is wrong regardless of what's built on top.

## 7. The Role Card Test

Does the design answer the question: "What does this product believe about its users and their time?"

A product that treats users as experts uses dense, keyboard-driven, efficient UI. A product that treats users as occasional visitors uses progressive disclosure, friendly empty states, and celebration moments. A product that treats users as professionals values precision over delight.

**How to apply:** state in one sentence what this UI believes about its users. Then check whether every major decision is consistent with that belief. Contradictions (dense data grid next to playful emoji micro-copy) signal an unsettled product identity.

---

These tests are checks, not scores. A test result of "fail" means: name the specific element, name why it fails the test, name the fix. "I squinted and it looked fine" is not a pass — describe what you saw.
