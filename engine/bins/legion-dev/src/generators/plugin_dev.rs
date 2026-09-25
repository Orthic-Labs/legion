//! Port of `scripts/plugin-dev.mjs`.
//!
//! The JS version shells out to `node scripts/verify-plugin-parity.mjs
//! --check` as a subprocess and relays its stdout/stderr. This port calls
//! the in-process Rust port directly (`verify_plugin_parity::run_opts`)
//! rather than spawning `legion-dev verify-plugin-parity` as a child
//! process, since both run in the same binary; the printed messages and
//! exit behavior match.

use std::path::Path;

use super::verify_plugin_parity;

pub fn run(root: &Path) -> bool {
    if !verify_plugin_parity::run_opts(root, true, false) {
        eprintln!("\nLive plugin surface does not resolve — fix the above before loading it.");
        return false;
    }

    println!(
        "\nLoad the live plugin (not the installed cache):\n\n    claude --plugin-dir {}\n\nThen in-session, after editing skills/agents/hooks/MCP:\n\n    /reload-plugins\n\nKeep the marketplace install disabled while developing so the two do not both\nown the harness. Bump the version only for a real release, which regenerates the\nsurface digest via 'npm run plugin:surface'.",
        root.display()
    );
    true
}
