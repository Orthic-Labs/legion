# Avatar Video

Keep voice, avatar identity, lipsync, and final video rendering as separate decisions. Use GenRight/current pipelines.

## Current Default

- Talking head from face image plus external audio: current InfiniteTalk-style route.
- Custom voice: generate or select a WAV first through GenRight Voice Studio/current TTS route.

## HeyGen, Only When Model Keys Exist

- New personal digital twin: `heygen-digital-twin-create`
- Photo avatar creation: `heygen-photo-avatar-create`
- Prompt avatar creation: `heygen-prompt-avatar-create`
- Existing avatar ID plus script/audio: `heygen-avatar-video`
- Source video plus audio lipsync: `heygen-lipsync-speed` or `heygen-lipsync-precision`

If the required key is missing from GenRight model metadata, do not fake the route. Report the missing model and offer the current InfiniteTalk/current pipeline alternative.

## Provider Gates

- If HeyGen requires consent, surface the consent URL/status and wait for completion.
- If API plan/account access rejects digital-twin creation, report that gate and offer photo/prompt avatar or current alternatives.
- Do not put HeyGen-specific settings outside the normal GenRight form-contract rendering.
