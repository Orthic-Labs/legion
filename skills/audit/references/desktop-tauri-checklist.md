# Desktop / Tauri checklist — cues for `correctness`, `performance`, `security`, `resilience`, `platform-parity`

House reference for local-first desktop apps (every Right Suite app). Carried by the lenses when the
target has `src-tauri/` or is otherwise a desktop/daemon app. Every cue below is greppable — cite a
real `file:line` per the hard rules. Source: 2026-07 six-model audit bake-off (converged finding
classes /audit previously had no name for).

## 1. Concurrency / lock discipline (`correctness` + `performance`)

All one `rg` away:

- `std::sync::Mutex::lock().unwrap()` (or `.expect(`) inside an `async fn` — blocks the executor;
  also a poison-panic path. Want `tokio::sync::Mutex` or `lock_recover()`-style poison handling.
- Lock guard held across an `.await`, a DB transaction, or any O(table) work — checkpoint-inside-lock,
  full-scan-inside-lock.
- Non-`async` `#[tauri::command]` fn doing fs/db/network I/O — runs on the dispatch/UI thread
  (the launch-freeze class: `clear_history` doing SQLCipher deletes on the command thread).
- Blocking work in async context without `spawn_blocking` / `block_in_place`.
- `blocking_lock()` inside async code.
- Silent reader→writer fallback (a read path that quietly takes the write lock/connection).
- Spawned threads (`std::thread::spawn`) without a panic guard / join-error handling; channel drains
  that panic when the worker died; `panic = "abort"` interaction with lock poisoning.
- Thread inventory: which commands hold the runtime/global lock across blocking work.

## 2. Desktop-IPC waterfalls (`performance`)

- Sequential `await invoke()` chains that could be parallel (`Promise.all`).
- Event → full-refetch storms (backend event handler re-fetches the whole table/list).
- Post-action full-sync calls (mutation followed by a full state re-pull instead of applying the delta).

## 3. Env-var escape hatches (`security`)

- Enumerate `std::env::var` / `process.env` reads in the desktop app. Flag any release-reachable
  behavior switch (feature downgrade, guard bypass, history/logging toggle, power-command enable)
  that lacks `#[cfg(debug_assertions)]` or an equivalent release gate.
- The web-centric authn/IDOR/XSS taxonomy misses this class entirely — it is the desktop analogue
  of a debug backdoor.

## 4. Tauri config posture (`security` / `release-readiness`)

- Prod CSP carrying dev origins (`localhost`, `ws:`, `devtools`) in `tauri.conf.json`.
- Capabilities/allowlist wider than the command surface actually used.
- Entitlements: `disable-library-validation`, missing sandbox, broad file-scope grants.
- Updater config: `plugins.updater.pubkey` present and equal to the suite pubkey (`29395F9FF466261D`);
  endpoints https; no per-app key drift.
- IPC surface: `generate_handler![...]` vs frontend `invoke("...")` — uncalled registered handlers
  (dead attack surface: registered, zero callers, often zero validation) and unregistered invokes
  (dead UI path). Deterministic input: `facts.checks[contract_mirror]`. Verify wrapper indirection
  (a `const CMD = "..."` table) before flagging an "unregistered" invoke.
- Cross-language contract mirror (`schema` lens): hand-mirrored `contract.ts` vs Rust protocol
  structs — diff field/variant names; `tsc`/`mypy` are blind to a drifted hand-mirror.

## 5. Resilience / observability (the `resilience` lens core)

- Sidecar/child/daemon death or hang: watchdog? restart? RPC calls without timeouts?
- Crash recovery: journal/WAL replay on fresh AND corrupt state; partial-artifact cleanup on kill.
- Graceful shutdown: SIGTERM/window-close drains in-flight work, flushes DB, kills children.
- Backpressure: unbounded channels/queues between producer (audio/events) and consumer.
- Corrupt-file handling: config/DB/model file fails to parse → recover or brick?
- Offline/degraded network (static cues): client fetch sites without retry/backoff, no caching or
  last-known-good fallback (the update-check-hangs-startup class).
- Observability: persistent structured log file (rotating), errors actually reach it, a field bug is
  diagnosable post-hoc. No log file in a shipped desktop app is a finding.
- Fresh-install cold start: empty config dir + empty DB boots clean (runtime pass covers this for
  daemon-style apps; statically, look for unwrap on first-run reads).

## 6. Platform parity (the `platform-parity` lens core)

For one-codebase-two-platform apps (CLAUDE.md rule 14):

- Build the matrix: every `#[cfg(target_os)]` / `usePlatform()` branch × {macos, windows, linux-if-claimed}.
  Flag branches where one OS gets a stub (`Empty`, `unimplemented!`, silent `Ok(())`) while marketing/
  docs claim the feature cross-platform.
- Known classes: clipboard stubs, case-sensitivity asymmetries (revoke/compare paths), permission
  dead-ends (mic/accessibility prompt flows that exist on one OS only), caches never invalidated on
  one OS (`OnceLock` font cache), SRT/VTT export on one OS only.
- Per-OS CI: is each shipped OS actually built+tested in CI (Apple Silicon runner present)?
- Window chrome / hotkeys conform to the suite standard (`docs/RIGHT-SUITE-CROSS-PLATFORM.md`) —
  native overlay traffic lights on macOS, custom caption buttons on Windows, `<Kbd>` per-OS chords.

## 7. Rust `unsafe` inventory (`correctness` / negative-space)

- Deterministic input: `facts.checks[negative_space].meta.unsafe_sites` (per-file `unsafe` counts).
- For each cluster (WebView2/COM/Win32 FFI): does ANY test exercise the failure path (error HRESULT,
  null pointer, device removal), or are tests happy-path only? Untested `unsafe` error paths are a
  finding; the inventory itself goes in the report appendix.
