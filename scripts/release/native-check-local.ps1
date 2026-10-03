$ErrorActionPreference = 'Stop'
& node (Join-Path $PSScriptRoot 'local-build-route.mjs')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& rightkit cargo check --manifest-path engine/Cargo.toml --workspace --all-targets --locked --release --target x86_64-pc-windows-msvc
exit $LASTEXITCODE
