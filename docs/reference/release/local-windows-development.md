# Local Windows installer development

Adrian authorized local unsigned Legion installer development. Tracked
`.rightkit-local-development.json` limits this exception to
`Orthic-Labs/legion`, native Windows, & unsigned installer work.

From primary Legion checkout, run:

```powershell
pnpm run native:check:local
```

This is required before spending an installer build. It runs
`cargo check --workspace --all-targets --locked --release` for Windows MSVC
through managed RightKit. It uses same persistent external Cargo target &
compiler cache as release build, but performs no assembly, installer creation,
qualification, installation, signing, or publication.

After check passes, run:

```powershell
pnpm run release:local:win:unsigned
```

This command builds release binaries through managed RightKit, reusing its
persistent external Cargo cache. It assembles portable product, builds unsigned
Inno installer, runs isolated installed qualification, then installs exact
installer at `%LOCALAPPDATA%\Orthic Labs\Legion\current`. Final JSON records
source state, installer SHA-256, qualification evidence, installed root, version
& elapsed time.

Build only:

```powershell
pnpm run release:build:win:unsigned
```

Inno Setup 6 must be installed or `INNO_SETUP_PATH` must point to `ISCC.exe`.
Never set Cargo target variables, invoke direct Cargo, spoof CI, sign, publish,
or run Mac work in this local route.
