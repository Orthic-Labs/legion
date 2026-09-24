#!/usr/bin/env bash
# render-narration.sh · thin wrapper over the Rust port.
#
# All logic (timeline.json reads, render-video/-seek + mix-voiceover
# orchestration, ffmpeg invocation) now lives in
# `legion script designer/render-narration` (engine/bins/legion/src/commands/script.rs,
# w2_007::render_narration). This script stays only so existing docs/callers
# using `bash render-narration.sh ...` keep working.
#
# Usage: bash render-narration.sh <html> --timeline=<path> [options]
set -e
exec legion script designer/render-narration "$@"
