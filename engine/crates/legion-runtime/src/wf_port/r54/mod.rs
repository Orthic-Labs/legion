//! Packet r54: Rust port of `src/lib/qa-engine/qa.mjs`, the headless-Chrome QA CLI
//! (`--shot`/`--actions`/`--sweep`) that packet P9-skill-scripts's `p9_skills::qa` dispatcher
//! (`legion_runtime::p9_skills::qa`) forwards `node <engine script> ...argv` to.
//!
//! Module map (each mirrors a section of the 764-line original):
//! - `args`: `usage()`, `parseArgs()`, `parseViewport()`, `VIEWPORTS`, `THROTTLE`.
//! - `browser`: `findBrowser()`, `defaultStartCommand()`.
//! - `profiles`: `PROFILE_PREFIXES`, `sweepStaleProfiles()`.
//! - `ports`: `freePort()`, `waitForHttp()`.
//! - `session_client`: the `BrowserSession` trait standing in for qa.mjs's hand-rolled CDP
//!   client (`elementPoint`/`runtimeEval`/`waitForEval`/`capture`/`applyConditions`/
//!   `loadSession`/`saveSession`), so page-control logic is testable without a real browser.
//! - `chrome_session`: `headless_chrome`-backed production `BrowserSession` (best-effort; see
//!   its module doc — unverified against a real `cargo build` in this environment).
//! - `actions`: the action-file schema and `runAction()` dispatch.
//! - `session`: `--load-session`/`--save-session` file I/O.
//! - `run`: `main()`'s dispatch (`plan()`, `needsCdpShot`, URL/path assembly, process wiring).

pub mod actions;
pub mod browser;
pub mod chrome_session;
pub mod profiles;
pub mod ports;
pub mod run;
pub mod session;
pub mod session_client;

pub mod args;

pub use args::{parse_args, usage, Args};
pub use run::run;
