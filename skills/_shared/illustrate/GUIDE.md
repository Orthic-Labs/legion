# Biological-Mechanical Illustration

Create semantically coherent biological-mechanical illustrations in the approved shared drawing language. Preserve each product's identity while reusing one rendering system.

## Load

1. Read `references/style-contract.md` completely.
2. Read `references/tool-adapters.md` for the selected generator.
3. Use `assets/style-anchor.png` as the primary style reference.
4. Read the target brand entry in `/workspace/.claude/rules/brands.md` before choosing colors.

## Build the concept

1. Start with one universally readable physical verb: pull, trace, support, guide, cut, join, lock, balance, or route.
2. Describe the literal visible action in seven words or fewer without naming the product. Reject concepts that fail this test.
3. Reduce the message to one cause-&-effect sentence: `[input] passes through [mechanism], producing [outcome] under [agent/control]`.
4. Assign every visible object one semantic role. Remove any object that cannot be explained in one clause.
5. Never encode abstract nouns as arbitrary shapes. A viewer must understand the physical action before reading product copy.
6. Choose one biological structure & one mechanically plausible action. Make their interface visible.
7. Draw the mechanism as a working cutaway: show its load path, contact point, fastener, hinge, spring, bearing, valve, or guide where relevant.
8. Add a hand only when choice, extraction, control, or intervention is part of the concept.
9. Use one accent color only for the active path, selected item, or decisive state.
10. Reserve negative space for page copy without putting text inside generated art.

## Generate

1. Build the prompt from `references/tool-adapters.md`.
2. Treat the anchor as a rendering reference, not a composition template. Do not repeat its hand, cables, membrane, or pinch valve unless the new concept requires them.
3. Generate one focused production image by default. For exploration, generate three variants with different mechanisms, not cosmetic palette swaps.
4. Inspect the full frame & a detail crop. Reject incoherent anatomy, decorative machinery, accidental body horror, or unexplained objects.
5. Iterate one variable at a time: mechanism, composition, material treatment, or accent placement.
6. Save approved work inside the consuming project; never leave a project asset only in a generator cache.

## Acceptance gate

Approve only when all answers are yes:

- Can a viewer explain the action without reading copy?
- Can a viewer describe the literal action in seven words or fewer?
- Does every part have a purpose?
- Could the mechanical action physically work?
- Does biology read as dry, drawn structure rather than flesh?
- Does one accent identify one meaningful path?
- Does the image look illustrated rather than photographed or rendered?
- Does the result inherit the target product's colors without changing its locked identity assets?
