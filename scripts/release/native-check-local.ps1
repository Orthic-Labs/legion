$ErrorActionPreference = 'Stop'
& node (Join-Path $PSScriptRoot 'local-build-route.mjs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:RIGHTKIT_BUILD_MODE = 'dev'
$env:RIGHTKIT_CARGO_PROFILE = 'release-iterate'
Remove-Item Env:CARGO_INCREMENTAL -ErrorAction SilentlyContinue
& rightkit cargo check --manifest-path engine/Cargo.toml --workspace --all-targets --locked --profile release-iterate --target x86_64-pc-windows-msvc
exit $LASTEXITCODE
