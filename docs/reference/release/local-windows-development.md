# Windows unsigned installer development

Compile is always local, through the gate and the RustRight broker (Adrian; Orthic-Labs/legion#107;
`docs/rules/rightkit.md`, public-repository execution policy). A busy host queues in the broker,
which lends and reclaims units; it never hands the compile to CI. The former 30-minute
local-build route that forced GitHub CI is retired.

Signing: every build, dev included, is signed with the same identity (workspace rule). This
route builds an unsigned installer, so it is not run until RightKit's portable development
install signs the payload; see the readiness note in the daily-probe work (Orthic-Labs/legion#138).

CI qualifies only: push exact owned source to the existing `main` branch, or use an
explicitly authorized branch through manual dispatch. Do not create a branch
solely for this route. `.github/workflows/ci.yml` checks Windows & macOS. It checks whole
native workspace/all targets, tests native Codex Stop transport, builds unsigned
installer & runs isolated installed qualification. Download the `dev-windows-<sha>` artifact bound to
exact run/SHA, verify installer digest against qualification, then install exact
qualified artifact at stable `current` & verify requested installed behavior.
This route requires no signing, publication or Mac work. A CI artifact is not
proof of installation on the maintainer's machine.

The operator authorized local unsigned Legion installer development. Tracked
`.rightkit-local-development.json` limits this exception to
`Orthic-Labs/legion`, native Windows, & unsigned installer work.

Only after local idle admission, from primary Legion checkout run:

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

This command builds `xtask` through managed RightKit with an explicit native
target, resolves its executable from Cargo's `compiler-artifact` output, then
runs its existing installer workflow. Generic `cargo run` remains denied.
The workflow builds release binaries through managed RightKit, reusing its
persistent external Cargo cache. It assembles portable product, builds unsigned
Inno installer, runs isolated installed qualification, then installs exact
installer at `%LOCALAPPDATA%\Orthic Labs\Legion\current`. Final JSON records
source state, installer SHA-256, qualification evidence, installed root, version
& elapsed time.

Build only:

```powershell
pnpm run release:build:win:unsigned
```

If isolated qualification passes but stable install exits 4 with `untrusted mount
point` during activation, a packaged Codex shell has redirected LocalAppData
through its LocalCache. The installer rolls `current` back. Run the exact
qualified installer from a normal Windows host process (the Mac `win` bridge
can launch that Windows process), then verify `current` binary hashes against
the qualified assembly and exercise the hook. Do not copy binaries manually.

Inno Setup 6 must be installed or `INNO_SETUP_PATH` must point to `ISCC.exe`.
Never set Cargo target variables, invoke direct Cargo, spoof CI, sign, publish,
or run Mac work in this local route.

## Command rules

These rules moved here from the always-loaded Package Rules; they apply only to Windows
installer work.

- Before any Windows installer build, check whole native workspace/all targets on the selected
  build host with `pnpm run native:check:local`; a busy broker queues it.
- For Windows installer development, use `pnpm run release:local:win:unsigned` from the
  primary checkout after the native check passes. `.github/workflows/ci.yml` qualifies; it is
  not a fallback for a busy host. Both routes require unsigned
  installer, isolated installed qualification, then exact stable-`current` install.
- Use `pnpm run release:build:win:unsigned` only when build output is requested without install
  or qualification. Focused local tests supporting this route are allowed.
- Windows unsigned development CI is authorized; signing, publication & Mac work require
  explicit scope. CI success proves build/qualification only: download the exact qualified
  installer, reinstall stable `current`, and verify the requested installed behavior before
  claiming completion.
- These `pnpm` scripts call `powershell`; they do not run on a host without PowerShell (for
  example a Mac). On such a host use the GitHub CI route.
