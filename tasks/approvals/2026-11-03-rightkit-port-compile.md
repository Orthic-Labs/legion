# Approval request (PARKED): gate compile of the merged RightKit port

Commit: 6d97ad09 on main (local, unpushed). origin/main 28e71eca is merged in (it already ported research, review, minimize, evidence, policy, handoff to published RightKit crates). My earlier duplicate port commits were superseded by origin's.

## What this head holds beyond origin/main
sweep, daily dedupe, governor/hook rules, pnpm 12.16.1 JS-audit redesign, clippy -D warnings fixes (surviving files), rustfmt of merged files, refreshed secret-scan record.

## Class A (preflight, no approval needed)
Command: rightkit-host-gate --to check. Last full run on the previous head: /Volumes/D/scratch/legion-impl/classa/run14.log (107 scans, 104 pass, 3 fail); the secret-scan record is refreshed since (not rerun).
Failures remaining:
1. build-helpers:engine RK_BUILD_HELPER_WROTE_OUTSIDE rustls 0.23.46 (zig cache). Owner rkn, fix in @rightkit/release 0.6.30 + Mac sudo retrace (Adrian).
2. advisory-exceptions:engine RUSTSEC-2023-0071: rightkit-ownership 0.4.4 in Cargo.lock widens the suppression; entry lists 0.3.1 (stale). The gate says it needs fresh approval. This is origin's pin bump; Adrian decides whether to approve the widened suppression (not edited by me).
3. (fixed) rustfmt x8 and secret-scan record.

## Not ported (RightKit asks)
apple row: rightkit-apple-ops 0.1.1 needs rusqlite ^0.41 (via rightkit-db 0.5.3) but rightkit-evidence-decisions 0.1.0 needs ^0.40.2: one sqlite3 link per graph. Ask rkn: republish evidence-decisions (or apple-ops) on one rusqlite.
agent-policy, hooks, mcp, doctor, engine-host, qa/release xtask: features missing. wf_port: reclassify to a new rightkit-dispatch-validator crate (cloud agent). Unpublished: agent-orchestration, code-audit, github.

## Verdict
Will NOT pass today (items 1 and 2). After both clear, a compile slip is possible (merged clippy/format edits unverified), about 15%. No push, CI or release requested.

## Update 2026-11-03 (after dependency update)
Commit: 4cb75d3e (local, unpushed). Includes 737fee9e and 681d83d4 (advisory entry for RUSTSEC-2023-0071 lists rightkit-ownership 0.4.4; passes Class A) and the dependency update (docs/reference/deps/outdated-2026-11-03.md).
Class A: rightkit-host-gate --to check, 107 scans, 106 pass, 1 fail. Log: /Volumes/D/scratch/legion-impl/classa/run15.log
Only failure: build-helpers:engine RK_BUILD_HELPER_WROTE_OUTSIDE aws-lc-sys 0.47.0 (zig cache; fix is @rightkit/release 0.6.30 install + retrace, host step).
Traced before compile (read, not built): lopdf 0.46 (export_deck_pdf.rs, API identical), scraper 0.29 (SelectorErrorKind lifetime only; never named), getrandom 0.4.3 (fill unchanged, 12 sites), ed25519-dalek 3.0.0 (from_bytes/Signer/verify_strict unchanged; std feature removed; coexists with jsonwebtoken's 2.2.0).
Verdict: will not pass until the zig/trace blocker clears; after that, compile-slip risk is moderate (4 major bumps + 53 lock updates unverified by a build), about 20%.

## Update: pre-compile Oracle passes (2026-11-03, per the Orchestrator's bar)
Head: see git log (b66f736f + the freshness/warnings commit after it). Five read-only legion:oracle passes "as the compiler" and for warnings over the 347-file Rust diff vs origin/main (patches in /Volumes/D/scratch/legion-port/oracle/):
- legion-runtime: 0 compile, 0 warning findings.
- legion-audit: 0, 0 (getrandom 0.4.3 and ed25519-dalek 3.0.0 call sites checked against the new crate source).
- bins/legion rest + legion-host + legion-dev + xtask: 1 compile error (commands/mod.rs test lost the InventorySource import) and 2 clippy errors (setup_registry.rs windows_mklink_path cfg; run.rs redundant closure): fixed in b66f736f.
- new commands + legion-hook: 1 compile error (setup/freshness.rs used removed crate legion_effects; now rightkit_evidence_effects) and 4 clippy (3 useless_conversion, 1 redundant_closure): fixed.
Left, per policy "delete or cfg(test)": pre-existing #[allow(dead_code)] in production structs touched by the diff (bins/legion-dev native_cli_gate.rs:81, xtask qualify_windows/lifecycle.rs:135, plus older ones in audit_bench.rs, native_cli_gate.rs, xtask main/finalize/prepare/windows_qualify_installed/tree).
Unverified by reading (needs the compiler): sweep.rs:760-763 closure Ok(()) type inference; warnings 'likely' items.
Also not yet compiled: the #134 dispatch change (0578e8f6).
