# Article Illustrations

Use static image generation. Start with a shot list unless the user explicitly asks for direct generation.

For Chinese article art, "Xiaohei", "Ian style", "小黑", "怪诞", black-line conceptual illustrations, or 正文配图 requests, also read `xiaohei-illustration-style.md`. That reference is absorbed locally under this router; do not depend on an external skill or repo at runtime.

## Intake

- Article text, Markdown file, or concept
- Desired count, default 4-8
- Language, default Chinese when source is Chinese
- Output folder

## Output

- One image per cognitive anchor
- 16:9 white-background PNGs
- Final files saved into the requested workspace, then indexed/reviewed through GenRight Gallery when useful

## Style DNA

- Pure white background, no paper texture
- Minimal black hand-drawn line art
- Default recurring figure for Xiaohei-style Chinese art: small solid-black hand-drawn character with white dot eyes and thin legs
- The figure performs the core conceptual action and is not decorative
- Sparse red/orange/blue handwritten Chinese annotations when useful
- One image explains one core idea

Avoid PPT style, formal flowcharts, dense explainers, cute mascot posters, commercial vector style, and copied old-case compositions.

## Shot List Contract

For planning, output 4-8 image ideas by default. Use 1-3 for short posts and avoid exceeding 9 unless the user asks. Each shot should name:

- Placement after the relevant paragraph or section
- Theme and core idea
- Structure type, such as workflow, local system, before/after, role state, concept metaphor, layered method, route map, or mini comic
- What the recurring figure does
- Suggested objects and short Chinese labels

Do not average one image per paragraph. Pick cognitive anchors: a core judgment, a turn in the argument, an input/output loop, a split, a before/after, a handoff path, a common failure, or a visible state change.

## Route

- Codex with imagegen available: call `$imagegen` after writing the shot list and prompts.
- Claude or no-imagegen context: seed GenRight Image Studio/current image pipeline.
- Do not use the video pipeline unless the user asks to animate the illustrations.
