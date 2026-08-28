# Windows closure authority

## Raw operator scope

Remove development suffix from Legion version. Close Windows work only; Apple/macOS release work is explicitly out of this pass because it is configured on Mac. Finish Windows-native behavior, stable artifact production, live Windows install, Codex/Claude wiring, hooks, & WinGet readiness. Preserve user-owned skills/private data. Workers must never run Cargo, builds, tests, generators, installs, commits, pushes, merges, or heavy checks; current orchestrator owns every such action.

## Frozen facts

- Repository: `<repository-root>`
- Baseline: `445d85f87793fcc4978709b7c473e927db8f4d8a`
- Canonical version: `0.1.0`; baseline is clean & synchronized with `origin/main`.
- CI run `33119242090` passed Ubuntu, Windows, macOS, & private-repo guard.
- Live Windows binaries remain stale `0.1.0-dev.3` until orchestrator builds & installs stable output.
- `legion-hook` currently returns `enforcementHealth: unsupported` for valid requests.
- Codex & Claude live projections/cache are stale; repair must preserve unrelated user-owned directories.
- Windows signing environment currently lacks `signtool.exe`, `winget.exe`, `ARTIFACT_SIGNING_DLIB`, `ARTIFACT_SIGNING_METADATA`, & Azure signing variables.
- `@rightkit/release` `0.2.68` is current npm latest; its doctor rejects every hosted workflow, including right-git-managed `.github/workflows/ci.yml`. Cross-repository RightKit repair is owned by orchestrator, not these lanes.

## Acceptance owned by orchestrator

1. Valid hook requests receive a real deterministic policy result with strong enforcement; invalid frames fail closed.
2. Setup status & repair observe live executable/plugin/projection identity, refresh owned stale artifacts, remove only proven retired Legion projections, & preserve unrelated user data.
3. Windows release config supports explicit x86_64 & ARM64 artifacts, packaging, signing inputs, checksums, SBOM/notices/provenance/qualification references, & WinGet portable metadata without claiming signed/available before evidence exists.
4. Orchestrator runs all focused tests, Cargo checks/builds, release doctor/package verification, live install/repair, client/hook smoke checks, commits, pushes, CI, audit, & Oracle completion validation.
