# Rubric pack: Cargo.toml (`**/Cargo.toml`)

Loaded by `security`, `release-readiness`, and `minimize` when scoped files match. Cite the manifest
line. Where `cargo audit`, `cargo deny`, `cargo machete`, or `cargo outdated` ran, their logs are the
first evidence and this pack covers the rest.

## Dependencies and supply chain
- Dependencies from `git =` without a `rev` (a moving target) or from a fork or personal repository
  with no recorded reason; `path =` dependencies that escape the workspace root.
- Wildcard (`*`) or unbounded version requirements; for applications, a missing `Cargo.lock` in
  version control.
- A `[patch]` or `[replace]` section left over from debugging.
- Registry other than crates.io without an entry in the project's allow-list (`deny.toml` or equivalent).
- Duplicate major versions of the same crate in the lockfile that the manifest could unify.
- Crates that duplicate the standard library or an already-present dependency (`minimize`): one
  caller, one function, a lone feature of a heavy crate. Verify with `cargo tree -i <crate>` before
  suggesting removal.
- Default features enabled on heavy dependencies where the code uses a small subset
  (`default-features = false`), and `features = ["full"]` on tokio-style crates in a library.
- Dev-only crates listed under `[dependencies]`, and build-only crates under `[dependencies]`
  instead of `[build-dependencies]`.

## Workspace hygiene
- Workspace members with their own copies of a version that `[workspace.dependencies]` already pins.
- `edition` and `rust-version` inconsistent across members, or `rust-version` absent on a published crate.
- Missing `license` / `license-file`, `repository`, or `description` on a crate meant for publication;
  `publish = false` missing on internal crates that must not be published by accident.
- `[lints]` / `[workspace.lints]` absent when CI relies on `-D warnings` through flags only.

## Profiles and release
- `[profile.release]` choices (`panic = "abort"`, `lto`, `codegen-units`, `strip`, `debug`) that
  contradict documented behaviour: `panic = "abort"` with code that catches unwinds, `strip` with
  symbolication needs, debug info shipped in a release artifact.
- `overflow-checks` / `debug-assertions` switched off in a profile used for shipped builds without a note.
- `build.rs` or proc-macro dependencies that fetch the network or run arbitrary tools at build time.
- Version bumped without a changelog entry or without the lockfile updated in the same change.

## Not findings
- A pinned `=x.y.z` requirement that the project documents as deliberate.
- Feature flags that exist only for tests.
