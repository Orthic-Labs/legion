---
name: content-transcription
description: Transcribe Instagram reels, YouTube videos, TikToks, or local media through ScrapeRight. ScrapeRight is the source of truth; Parakeet TDT is the primary ASR path.
---

# Transcribe — ScrapeRight

Use ScrapeRight dogfood for agent-run transcription. Do not use the old Python Whisper pipeline unless Adrian explicitly asks for legacy behavior.

```powershell
cd D:\Claude\scraperight
$env:SCRAPERIGHT_ASR_ENGINE='tdt'
$env:SCRAPERIGHT_FFMPEG='D:\Claude\bin\ffmpeg.exe'
$env:SCRAPERIGHT_TDT_MODEL_DIR='D:\Claude\scraperight\models\asr\parakeet_tdt_v3_static_b64'
$env:ORT_DYLIB_PATH='D:\Claude\scraperight\src-tauri\resources\runtime\onnxruntime.dll'
.\target\debug\dogfood.exe --output .cache\dogfood\<run-name> --reel "<URL>"
```

Outputs live under `D:\Claude\scraperight\.cache\dogfood\<run-name>`.

After running:
1. Read `dogfood-results.json`.
2. Confirm `asr backend: parakeet-tdt-v3`.
3. Copy useful `.txt` transcripts into `D:\Claude\tools\pipelines\transcribe\transcripts\`.
4. Update `url_index.json` and `tag_transcripts.py`.
5. Write/update the dated bucket summary under `D:\Claude\Roadmap\transcripts-research\`.

Notes:
- TDT may emit text, JSON, SRT, and VTT depending on current ScrapeRight support.
- Instagram empty media/auth failures are download-layer failures, not ASR failures.
- For batches, run one reel per dogfood invocation; the CLI currently accepts only one effective `--reel`.
