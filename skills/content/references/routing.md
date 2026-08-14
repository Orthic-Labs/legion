# Routing

Local anchors:

- `D:/Claude/genright`
- `D:/Claude/genright/README.md`
- `D:/Claude/docs/video-pipeline-guide.md`
- `D:/Claude/docs/IMAGE-PIPELINE-GUIDE.md`
- `D:/Claude/tools/skills/.system/imagegen/SKILL.md`

## Core Rule

This skill chooses a path. It does not implement providers. Provider spend only happens through GenRight/current guarded pipeline preflight and approval, or through Codex `$imagegen` when that tool is available for static image generation.

## Runtime Detection

- In Codex, use `$imagegen` for simple static image generation when the image generation tool is available.
- In Claude or no-imagegen contexts, use GenRight Image Studio/current image pipeline for static images.
- For video, route through GenRight Video Studio/current video pipeline.
- For HeyGen, inspect GenRight model metadata or local docs first. Missing, unparsable, or old metadata means hide HeyGen choices and use current alternatives.

## HeyGen Model Keys

Use these names only when present:

- `heygen-digital-twin-create`
- `heygen-photo-avatar-create`
- `heygen-prompt-avatar-create`
- `heygen-avatar-video`
- `heygen-lipsync-speed`
- `heygen-lipsync-precision`

Run/ref kinds:

- `avatar_create`
- `avatar_video`
- `video_lipsync`

If a key is absent, report the missing route briefly and offer the current GenRight/current-pipeline alternative.
