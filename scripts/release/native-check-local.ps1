$ErrorActionPreference = 'Stop'
& rightkit cargo check --manifest-path engine/Cargo.toml --workspace --all-targets --locked --release --target x86_64-pc-windows-msvc
exit $LASTEXITCODE
