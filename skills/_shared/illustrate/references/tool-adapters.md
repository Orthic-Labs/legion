# Tool Adapters

## Master prompt block

Fill every bracket before generation:

```text
Create a wide hand-drawn biological-mechanical illustration for [product/section].

Meaning: [one cause-&-effect sentence].
Scene: [input] enters or meets [living structure]. A mechanically credible [mechanism] visibly [action]. [outcome or human action] completes the idea.
Composition: [direction of action], one dominant focal point, density contrast from [complex zone] to [calm zone], with clean negative space at [copy region]. No text.
Materials: dry biological structure in warm ivory & smoke blue-gray; graphite & dull-steel mechanics; [brand accent] used only on [meaningful active element].
Rendering: precise graphite & pen-and-ink contours, fine cross-hatching, restrained colored-pencil & flat gouache washes, visible matte paper tooth, shallow cutaway depth, controlled hand-drawn irregularity.
Functional requirements: every object has a semantic role; mechanism shows believable force transfer & mounting; anatomy is coherent; active path is immediately readable.
Avoid: [paste relevant hard negatives from style-contract.md].
```

Add this reference instruction whenever the tool accepts images:

```text
Use the attached reference for drawing medium, line density, matte materials, tonal restraint, & semantic clarity only. Do not copy its hand, cables, membrane, pinch valve, or layout unless requested.
```

## Codex ImageGen

1. Use the `imagegen` skill & built-in image generator.
2. Pass `assets/style-anchor.png` through `referenced_image_paths`.
3. Send the completed master prompt plus the reference instruction.
4. Generate separate calls for distinct concepts or variants.
5. Inspect & save the selected image inside the target project.

## Nano Banana API

Nano Banana's local backend requires public HTTP(S) reference URLs. Upload a copy of `assets/style-anchor.png` to the studio's durable reference store, then use that URL consistently. Do not publish or overwrite the durable reference without owner authorization.

For the current image-gen router, include `@img1` in the prompt & pass the same URL as `styleRef`:

```js
await router.generate({
  prompt: `@img1 ${completedMasterPrompt}`,
  aspect: 'landscape',
  outPath,
  intent: 'premium',
  styleRef: '<PUBLIC_HTTPS_ANCHOR_URL>',
  resolution: '2K',
});
```

For Nano Banana UI, upload the anchor directly & paste the completed master prompt. Describe it as a style reference, not an edit target.

## Other image tools

1. Attach `assets/style-anchor.png` in the tool's style-reference or image-prompt slot.
2. Set reference influence to medium when adjustable. Preserve drawing language without copying composition.
3. Paste the completed master prompt.
4. If the tool supports separate negative prompts, move the `Avoid` line there.
5. If the tool accepts no image reference, prepend this prompt-only fingerprint:

```text
Hand-drawn field-guide engineering plate: precise graphite & ink contours, fine cross-hatching, dry matte paper tooth, restrained colored-pencil & flat gouache washes, warm ivory & smoke blue-gray biological structures, dull graphite mechanics, shallow engineering-cutaway depth, one semantically meaningful accent, no photorealism or glossy CGI.
```

## Critique prompt

Use this after generation:

```text
Explain this image literally from input to mechanism to outcome. List every visible object that lacks a clear role, every mechanically impossible connection, every biological form that reads as flesh or body horror, every decorative accent, & every place where reference composition was copied instead of adapted. Return KEEP, REVISE, or REJECT with one highest-value change.
```
