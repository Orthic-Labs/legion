# Motion Graphics

Use SampleApp Video Studio/current video pipeline. This branch creates a storyboard and normal video preflight seed, not a provider-specific request.

This absorbs the useful parts of the old motion-design workflow without carrying over provider-specific tool calls, connector names, or hardcoded external model APIs.

## Intake

- Brand or project
- Project slug
- Aspect: `9:16`, `16:9`, or `1:1`
- Duration target: usually 5s teaser/logo sting, 10s post/story, or 15s promo/product video
- Flow type: `classic_motion` or `kinetic_motion`
- Asset refs: logo, product, start/end image, or video refs
- Mood/style
- End card or logo lock requirement

Ask for missing essentials together in one compact intake when they change the storyboard or route. If the brief already implies the answer, proceed and record the assumption.

## Output

- Compact storyboard
- Optional storyboard-sheet prompt with 6, 8, or 9 panels if a visual planning frame is useful
- Start/end frame prompts or selected refs
- Normal SampleApp Video Studio preflight payload
- Shot contract template or inline contract

## Flow Types

### `classic_motion`

Use for standard ads, brand promos, service explainers, logo reveals, and atmospheric product/service presentations.

- Smooth transitions
- Restrained camera movement
- Elegant typography zones only when text can be handled deterministically
- Clean opener/closer logo lock
- Cinematic but legible pacing

### `kinetic_motion`

Use for sports promos, tech product launches, music teasers, AI capability demos, fashion drops, and high-energy social ads.

- Fast cuts and stronger match cuts
- More aggressive camera moves
- Peak-action freeze frames and material transformation moments
- Hard stop logo lock at the end
- Avoid realistic humans unless the user supplied approved human refs; prefer silhouettes, chrome figures, abstract 3D forms, product geometry, or graphic materials

For kinetic clips, reserve a static logo/name hold in the final beat: about 1s for 5s clips, about 2s for 10s clips, and about 2-3s for 15s clips.

## Storyboard Guidance

When a storyboard is needed, create a sequence from opening to build to climax to resolution/logo lock. Each frame should include:

- Camera position
- Subject/material state
- Motion state, blur, freeze, transition, or cut
- Asset/ref usage
- Any text that must be deterministic later instead of trusted to AI video

If making a storyboard sheet prompt, generate one sheet concept, not separate provider calls per panel. The sheet is a planning artifact; final rendering still goes through SampleApp/current pipeline preflight and eyes review.

## Model Defaults

- Product/social anchored motion: prefer the cheap draft route exposed in SampleApp/current contracts.
- Premium anchored motion: use the premium anchored route only when product fidelity or launch quality justifies it.
- Cheap b-roll: use only when product/human fidelity is not important.
- Avatar/talking head: current InfiniteTalk-style route unless HeyGen model keys are available.

## Prompt Rules

- Classic motion: smooth transitions, restrained camera, clean logo/end lock.
- Kinetic motion: faster camera and stronger match cuts.
- Do not rely on AI video for readable text, UI demos, captions, or deterministic typography; route those to Remotion later.
- Do not mention or use unapproved motion providers.
- Do not call connector/provider tools from this skill. Seed a SampleApp/current-pipeline preflight instead.
