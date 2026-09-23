//! Port of `skills/designer/engine/scripts/live-browser-dom.js`,
//! `live-browser-session.js`, `live-browser.js`, `live-commit-manual-edits.mjs`
//! and `live-complete.mjs` (chunk w2_017).
//!
//! ## Scope note (read this before extending)
//!
//! `live-browser-dom.js` and `live-browser-session.js` are helper bundles that
//! are served *into a live browser page* and evaluated by the page's own JS
//! engine (they attach to `window.__IMPECCABLE_LIVE_DOM__` /
//! `window.__IMPECCABLE_LIVE_SESSION__` and are driven through CDP
//! `Runtime.evaluate`). `live-browser.js` (11k+ lines) is the full in-page
//! overlay UI built on top of them. None of the three can be "ported to Rust"
//! in the sense of replacing their runtime: Rust does not execute inside the
//! target page's JS VM, and the DOM-touching parts of these files
//! (`getBoundingClientRect`, `closest`, `classList`, `addEventListener`,
//! `localStorage`, overlay DOM construction, CDP event wiring, ...) have no
//! meaning without a live DOM. Those files stay JS and continue to be
//! injected into the browser page as today; this module does not attempt to
//! replace that runtime.
//!
//! What *is* ported here, faithfully, is the pure (non-DOM, non-I/O) logic
//! those files contain, plus the pure logic in the two Node-side CLI scripts:
//!
//! - [`browser_dom`] — the deterministic string/geometry helpers from
//!   `live-browser-dom.js` (`desc`, `rectIsUsableAnchor`, `cssId`) that do not
//!   require a live `Element`.
//! - [`session`] — `live-browser-session.js`'s
//!   `createLiveBrowserSessionState`, ported against an injectable
//!   key/value store trait in place of `localStorage` (same read/write/JSON
//!   semantics, same key derivation, same checkpoint-revision bump behavior).
//! - [`commit_edits`] — the pure verification/matching helpers from
//!   `live-commit-manual-edits.mjs` (arg parsing, entry/candidate
//!   summarization, locator/text-window verification). The surrounding CLI
//!   (`commitManualEdits`, `repairPostApplyValidation`, filesystem rollback
//!   scanning, the copy-edit agent call) depends on sibling scripts
//!   (`live-manual-edit-evidence.mjs`, `live/manual-edits-buffer.mjs`,
//!   `lib/is-generated.mjs`, `live-copy-edit-agent.mjs`) that are outside
//!   this chunk's owned files and are not ported here.
//! - [`complete`] — `live-complete.mjs`'s argument parsing and durable-event
//!   construction. The server round trip (`fetch` to the local live server)
//!   and the local `createLiveSessionStore` fallback depend on
//!   `live/session-store.mjs` and `lib/impeccable-paths.mjs`, also outside
//!   this chunk; [`complete::CompletionEvent`] models the same event shape
//!   those scripts would append.

pub mod browser_dom;
pub mod commit_edits;
pub mod complete;
pub mod session;
