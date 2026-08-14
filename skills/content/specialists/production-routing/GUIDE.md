---
name: contentcreation
description: Routes content creation requests to the right existing image, video, motion graphics, avatar, lipsync, voiceover, or article illustration workflow. Use this skill whenever the user asks for content assets, GenRight creative workflows, motion design, motion graphics, animated ads, avatar videos, HeyGen, lipsync, cloned voice/TTS, Xiaohei/Ian-style article illustrations, black-line conceptual illustrations, or imagegen routing, even if they do not explicitly say "contentcreation."
---

# Contentcreation

Use this as a router, not a provider implementation. Pick the lightest existing path that can make the asset, then follow that path's normal preflight, approval, review, and gallery rules.

## Start Here

1. Read `references/routing.md`.
2. If the request is branch-specific, read exactly one matching reference:
   - Static/article art: `references/article-illustrations.md`
   - Xiaohei / Ian-style Chinese article art: `references/article-illustrations.md`, then `references/xiaohei-illustration-style.md`
   - Motion graphics, promo video, animated ad: `references/motion-graphics.md`
   - Avatar, talking head, HeyGen, lipsync: `references/avatar-video.md`
3. For brand-specific work, load the relevant brand rules before creating prompts or assets.
4. Keep provider execution inside GenRight/current guarded pipelines, except Codex static image work may use `$imagegen` when the tool is available.

## Route Decision

| Request | Default route |
|---|---|
| One-off static image in Codex | `$imagegen`, then save into the requested workspace |
| Static image in Claude or batch context | GenRight Image Studio/current image pipeline |
| Article illustrations | Read `article-illustrations.md`, produce a shot list first, then use `$imagegen` in Codex or GenRight Image Studio/current image pipeline otherwise |
| Xiaohei / Ian-style article illustrations | Read `article-illustrations.md` plus `xiaohei-illustration-style.md`; keep it inside this router, never as a separate skill dependency |
| Motion design / motion graphics / animated ad | Read `motion-graphics.md`, seed GenRight Video Studio/current video pipeline |
| Text-heavy typography, UI demos, deterministic brand motion | Remotion later; do not force AI video |
| Voiceover / cloned voice / TTS | GenRight Voice Studio/current TTS route when available; output WAV first |
| Avatar / talking head today | GenRight Video Studio with current InfiniteTalk-style route |
| HeyGen avatar or lipsync | Use HeyGen only after the model key appears in GenRight model metadata |

Ask one short clarifying question only when the answer changes the tool path. Otherwise default static image requests to `$imagegen` in Codex and video requests to GenRight/current guarded pipelines.

## Guardrails

- Do not add provider scripts, direct provider URLs, new queues, or API calls in this skill.
- Do not mention or route to unapproved motion providers.
- Do not bypass preflight, shot contracts, cost checks, operator approval, or eyes review.
- Do not copy long runbooks into outputs; cite the local docs and use the existing pipeline.
- Do not create standalone Xiaohei or motion-design skills. Their usable guidance lives under this router.
- For Stunning Strangers, keep work non-commercial and reference-only.

## Validation

Before claiming the skill is ready after edits:

```powershell
py -3.11 D:/Claude/tools/skills/.system/skill-creator/scripts/quick_validate.py D:/Claude/tools/skills/content
```

Use `references/smoke-checklist.md` for route-decision smoke checks. No paid provider calls are part of skill validation.
