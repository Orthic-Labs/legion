//! Port of `skills/alchemist/scripts/{parse_events.py,run-worker.sh,run-worker.ps1,
//! start-stack.vbs,tray.ps1}` (chunk w2_001).
//!
//! `parse_events.py` is ported in full: `first_text`, `classify`, BOM
//! stripping, JSONL parsing and the `--summary` report format all have
//! direct Rust equivalents below, with unit tests mirroring the Python
//! module's own behaviour (see `parse_events`).
//!
//! `run-worker.sh` / `run-worker.ps1` are OS process launchers (subprocess
//! spawning, watchdog timers, named mutexes, `omniroute launch-codex`
//! invocation). Spawning a child process is inherently host-specific and
//! not meaningfully unit-testable as ported Rust logic, so this chunk ports
//! only their **pure, testable decision logic** — the pieces both scripts
//! independently implement and that a caller-supplied process runner would
//! need — under `worker_launch`: Codex profile `model =` extraction (same
//! regex intent as both scripts' `sed`/`[regex]::Match`), the OmniRoute
//! `/healthz` status-code classification that decides "gateway is up" vs.
//! exit code 4, brief (stdin payload) validation, the documented exit-code
//! contract, sandbox/full-access argument selection, and the leading
//! JSON-preamble/BOM stripping the PowerShell runner applies before handing
//! lines to `parse_events.py`. The actual `omniroute launch-codex`
//! subprocess invocation, timeout watchdog, and named-mutex worker-slot
//! pool are left unported: they are process-orchestration side effects with
//! no return-value contract to assert against, and belong in an
//! integrator-owned binary that already has a process-spawning surface.
//!
//! `start-stack.vbs` (Windows Startup-folder launcher for the OmniRoute
//! gateway + Alchemist viewer + tray) and `tray.ps1` (the NotifyIcon tray)
//! are Windows GUI/process-launch scripts with almost no pure logic beyond
//! the URLs they probe and the up/down status text they render. Those are
//! ported under `stack_status`: the two service URLs, the idempotent
//! "start only when nothing already answers" decision, and the exact
//! status-line/tooltip text format both scripts print. Shelling out to
//! `where`, `wscript.exe`, `powershell.exe`, spawning the NotifyIcon, and
//! polling `Win32_Process` for a running `tray.ps1` are process/GUI side
//! effects, not ported.

pub mod parse_events;
pub mod stack_status;
pub mod worker_launch;
