---
name: content-seedance
description: >
  Seedance 2.0 AI video generation — cinematic motion shots Remotion can't produce (fluid motion,
  fabric/water, camera moves with depth). Runs ONLY through the locked WaveSpeed video pipeline
  (NEVER raw fal — fal is Veo-only). Use when user says "/content seedance", "AI video", "video gen",
  "cinematic shot", "faceless short". Requires WAVESPEED_API_KEY (set at User level).
---

# Seedance 2.0 Video Generation

Seedance runs **through the locked AI Video Ad Pipeline only** — never as a standalone curl.

## Backend lock (HARD — read `D:/workspace/.claude/rules/video-pipeline.md` first)

- **Seedance 2.0 = WaveSpeed.** fal is **Veo 3.1 ONLY**. There is NO `fal.run/fal-ai/seedance` path — that backend split is locked (PIPELINES.md §2.E, locked 2026-05-03). Calling fal for Seedance is wrong and is rejected by the router.
- Backend: `tools/backends/wavespeed.js` (Kling 3.0 Pro, Seedance 2.0 Fast+Std, HappyHorse, Wan, InfiniteTalk). FLF anchor param for Seedance = `last_image`.
- Model keys: **`seedance-2-fast`** ({480p: $0.10, 720p: $0.20, 1080p: $0.50}/s) — budget social tier, or **`seedance-2-std`** ({480p: $0.12, 720p: $0.24, 1080p: $0.60}/s) — higher quality. Resolution-tiered models THROW if no `resolution` is passed (no silent default).
- Key required: `WAVESPEED_API_KEY` (NOT `FAL_KEY`).

## Mandatory gates (enforced by the runner — you cannot skip them)

Every Seedance I2V call goes through these. The pipeline throws or halts if any is missing:

1. **shot_contract (preflight).** No I2V call fires without a validated `shot_contract` block. `runStage3Animate` throws at preflight before any API spend. Schema: `tools/recipes/video/prompt-contract.json`; renderer: `tools/pipelines/video/lib/prompt-contract.mjs`. Seedance renders as timestamp blocks `[00:00-00:0X]`. `audio_lock.mode = "lipsync_to_external_vo"` is NOT valid for Seedance (HappyHorse/InfiniteTalk only).
2. **Cost preflight.** `estimateBatchCost` in `create.mjs` prints line items + total before the first API call. Tiered models require `item.resolution` or it throws.
3. **Per-clip dual-juror QA.** Frame-by-frame review on **BOTH Opus AND Sonnet in parallel** via `mcp__claude-video-vision__video_watch` (≥3 fps, identical frame set). Single-juror is forbidden — divergence is the signal.
4. **the operator taste / eyes gate.** `tools/lib/human-eyes-gate.mjs` halts the pipeline at every taste-critical artifact (storyboard frames, per-clip QA, final cut) until the operator explicitly approves. AI suggests, jurors score — **only the operator approves**. No agent can approve on his behalf.
5. **Assembly re-encodes** through the concat filter (`scale + pad + setsar=1 + fps + format=yuv420p`), never `-c copy`. Final cut also dual-juror + eyes-gated before delivery.

## Seedance vs Remotion

| Need | Tool |
|---|---|
| Text on screen, kinetic typography, UI demos, captions, app-state changes | Remotion (I2V hallucinates UI — never ask it) |
| Brand color motion that's deterministic | Remotion |
| Cinematic shots: water, fabric in wind, real body/face motion | Seedance |
| Camera moves with parallax + depth | Seedance |
| Hybrid: Seedance hero composited into Remotion | Both |

## Workflow

1. `/brand <DD|RH|HR|TS>` — load the brand visual system. (No SS — SS is a passion project; no commercial video.)
2. **Storyboard START + END frames** for each shot via NB2 (`create.mjs --step=1`). Single-frame I2V drifts; both anchors are required.
3. **Author the `shot_contract`** (inline or from a `Content/<venture>/shot_contract_templates/` baseline). Compose the prompt from `tools/recipes/video/` recipes — never invent vocabulary.
4. **Animate via the pipeline** (Seedance on WaveSpeed):
   ```bash
   node tools/pipelines/video/create.mjs --step=2 \
     --image=out/shot1_start.png --end=out/shot1_end.png \
     --motion="..." --model=seedance-2-fast --resolution=720p \
     --duration=4 --aspect=9:16 \
     --shot-contract=out/shot1.contract.json \
     --out=out/shot1.mp4
   ```
   The runner validates the contract, runs the cost preflight, routes to WaveSpeed, and emits a `<clip>.prompt.json` audit sidecar.
5. **Faceless YT/IG Shorts** → use the fast-path instead of hand-authoring shots:
   ```bash
   node tools/pipelines/video/faceless-shorts.mjs   # builds the manifest (default backend seedance-2-fast)
   node tools/pipelines/video/campaign.mjs --manifest=<emitted manifest path>
   ```
   Captions are composited in Remotion, never asked of Seedance.
6. **Per-clip dual-juror QA → the operator eyes-gate → assemble → final dual-juror QA → final eyes-gate.** All enforced; do not present output as deliverable until the eyes-gate records APPROVE.

> If you cannot confirm the exact `--shot-contract` flag spelling for a given pipeline version, route to `create.mjs` / `faceless-shorts.mjs` and let it report its own usage — do NOT fall back to a raw curl.

## Brand prompt cheatsheet

### DD
- Lighting: low-key, single warm rim, deep shadows
- Camera: locked or slow push, never handheld
- Mood: considered, weighted, slightly dangerous
- Banned: bright, vibrant, cheerful, hi-energy

### RH
- Lighting: natural window, soft golden hour
- Camera: handheld with subtle drift
- Mood: honest, tactile, lived-in
- Subjects: fabric, hands, draped clothing

## Output
1. Prompt + shot_contract used (and the audit sidecar path)
2. Model key + resolution + clip file path
3. Cost preflight estimate + actual incurred (reconcile vs WaveSpeed invoice)
4. Dual-juror QA verdicts + eyes-gate status
5. Composite recommendation
