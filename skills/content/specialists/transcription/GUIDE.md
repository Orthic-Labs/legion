---
name: content-transcription
description: Transcribe Instagram reels, YouTube videos, TikToks, or local media through SampleApp. SampleApp is the source of truth; Parakeet TDT is the primary ASR path.
---

# Transcribe — SampleApp

Use SampleApp dogfood for agent-run transcription. Do not use the old Python Whisper pipeline unless the operator explicitly asks for legacy behavior.

```powershell
cd D:\workspace\sampleapp
$env:SCRAPERIGHT_ASR_ENGINE='tdt'
$env:SCRAPERIGHT_FFMPEG='D:\workspace\bin\ffmpeg.exe'
$env:SCRAPERIGHT_TDT_MODEL_DIR='D:\workspace\sampleapp\models\asr\parakeet_tdt_v3_static_b64'
$env:ORT_DYLIB_PATH='D:\workspace\sampleapp\src-tauri\resources\runtime\onnxruntime.dll'
.\target\debug\dogfood.exe --output .cache\dogfood\<run-name> --reel "<URL>"
```

Outputs live under `D:\workspace\sampleapp\.cache\dogfood\<run-name>`.

After running:
1. Read `dogfood-results.json`.
2. Confirm `asr backend: parakeet-tdt-v3`.
3. Copy useful `.txt` transcripts into `D:\workspace\tools\pipelines\transcribe\transcripts\`.
4. Update `url_index.json` and `tag_transcripts.py`.
5. Write/update the dated bucket summary under `D:\workspace\Roadmap\transcripts-research\`.

Notes:
- TDT may emit text, JSON, SRT, and VTT depending on current SampleApp support.
- Instagram empty media/auth failures are download-layer failures, not ASR failures.
- For batches, run one reel per dogfood invocation; the CLI currently accepts only one effective `--reel`.
