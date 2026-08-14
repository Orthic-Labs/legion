# Xiaohei Article Illustration Style

Local absorbed reference for Ian Xiaohei Illustrations. Source material was MIT licensed by Ian (2026); this file keeps the usable style guidance inside the `contentcreation` router so runtime work does not depend on a separate external skill or repo.

Use this only after `article-illustrations.md` when the request asks for Chinese article illustrations, Xiaohei, Ian style, 小黑, 怪诞, black-line conceptual art, 正文配图, or similar.

## Positioning

Create 16:9 horizontal Chinese article illustrations. The goal is not commercial illustration, PPT infographics, or cute cartoons. Turn a key judgment, workflow, structure, state, or metaphor from the text into a sparse, strange, readable hand-drawn explanation image.

The default recurring figure is 小黑: a solid-black, white-dot-eyed, thin-legged character with a blank serious expression. 小黑 is not a mascot or sticker. 小黑 must perform the core conceptual action in the image.

## Visual DNA

- Pure white background. No paper texture, warm gray, beige, gradient, shadow, noise, or retro paper feeling.
- Minimal black hand-drawn line art with slightly wobbly pen lines.
- Lots of white space. Aim for the main subject to occupy about 40%-60% of the canvas and keep at least 35% blank space.
- Sparse handwritten Chinese annotations. Use at most 5-8 labels, ideally 2-8 characters each.
- One image explains one core action, state, structure, or metaphor.
- Red marks key warnings, problems, emotion points, reminders, or results.
- Orange marks primary flow, paths, arrows, and A-to-B movement.
- Blue marks secondary notes, mental state, system state, AI/assistant hints, or feedback.
- Blue is optional. Use color sparingly.

Avoid commercial illustration, PPT infographics, formal flowcharts, course slides, cute mascot posters, children's illustration, complex architecture diagrams, polished flat vector art, tech UI, real app screenshots, complex backgrounds, and visible structure-type titles such as "Workflow", "系统架构图", "常见坑", or "路线图".

## Xiaohei IP

Xiaohei looks like a black bean, black box, small monster, shadow, hole, funnel, or irregular solid shape. It has white round dot eyes, tiny thin legs, occasional thin arms, and a deadpan serious expression.

Give Xiaohei a job:

- Carry, pull, push, sort, label, catch, stitch, cut, press, weigh, repair, guard, open, collect, or recycle.
- Operate a strange system component: a lever, gate, funnel, scale, path, machine, box, pipe, drawer, postbox, ladder, well, or black-box device.
- Be inside the metaphor, not beside it. If removing Xiaohei leaves the whole image equally clear, the prompt failed.

Do not make Xiaohei glossy, adorable, expressive, mascot-like, sticker-like, heavily costumed, childish, or more important than the structure it is explaining.

## Composition Patterns

Pick one structure type and keep it simple:

- Workflow: input -> strange processing -> output, often with orange flow arrows.
- Local system: 3-5 modules only; Xiaohei performs one key operation.
- Before/after: left side messy, right side stable, a clear transition in the middle.
- Role state: 2-4 small states that show pain, confusion, handoff, or relief.
- Concept metaphor: one memorable strange object or machine with a small input and output.
- Layered method: stacked boxes or blocks, not a formal pyramid; Xiaohei builds or carries part of it.
- Route map: a curved path with a few nodes; Xiaohei walks, drags, or repairs the route.
- Mini comic: 2-4 panels, each with one action.

Invent a fresh metaphor from the current article:

1. Convert the abstract concept into a physical action: stuck, leaking, sorting, settling, fermenting, opening, folding, unpacking, returning, weighing.
2. Convert the system into a low-tech object: broken machine, paper box, drawer, pipe, postbox, odd gauge, scale, well, ladder, weird workstation.
3. Make Xiaohei perform the action: pull the wrong wire, guard a gate, patch a pipe, record a state, lift a box, or feed something into a strange device.

Do not reuse old stock compositions unless the user explicitly asks to replicate one. Examples to avoid by default: two breakpoint conveyor belts, a judgment lever inside a content machine, funnel-sorting traffic/trust/conversion, cutting a material fish, dragging a handoff path, pulling three information sources, three figures holding horn/bridge/door, stamping a script toolbox, or holding a sign near a common-pitfall route.

## Prompt Packet

For each image, write a compact prompt with these fields:

```text
Generate one standalone 16:9 horizontal Chinese article illustration.

Visual DNA:
Pure white background. Minimalist black hand-drawn line art. Slightly wobbly pen lines. Lots of empty white space. Sparse red/orange/blue handwritten Chinese annotations. Clean absurd product-sketch feeling. No gradients, shadows, paper texture, complex background, commercial vector style, PPT infographic look, cute mascot poster, children's illustration, or realistic UI.

Recurring character:
小黑, a small solid-black absurd creature with white dot eyes, tiny thin legs, blank serious expression, and slightly uneven hand-drawn body. 小黑 must perform the core conceptual action, not decorate the scene. Serious, deadpan, slightly bizarre, not cute.

Theme:
{theme}

Structure type:
{workflow | local system | before/after | role state | concept metaphor | layered method | route map | mini comic}

Core idea:
{one sentence}

Composition:
{where 小黑 is, what 小黑 does, main object, and how information/material moves}

Suggested elements:
{3-5 objects}

Chinese handwritten labels:
{3-6 short labels}

Color use:
Black for line art and 小黑. Orange for the main flow/path/arrows. Red only for key warnings/problems/results. Blue only for secondary notes or system/feedback state.

Constraints:
One image explains one core structure. Main subject around 40%-60% of canvas. At least 35% blank white space. At most 5-8 short handwritten Chinese labels. No top-left title. Do not write the structure type on the image. Do not make it a formal diagram, course slide, dense explainer, cute poster, or copied prior composition. Invent a fresh visual metaphor for this article.
```

## QA

Regenerate or edit if:

- Xiaohei is missing or decorative.
- The image is not 16:9 horizontal.
- The background is not clean white.
- The layout looks like PPT, a course slide, a formal flowchart, or a dense explainer.
- There are too many nodes, arrows, labels, or explanatory text blocks.
- Chinese labels are unreadable or typo-heavy.
- Color is overused or semantically wrong.
- The image feels cute, childish, polished-commercial, or dead instead of strange and clean.
- The metaphor copies an old case instead of the current article.

Good output should feel a bit strange at first glance, then become understandable within a second.
