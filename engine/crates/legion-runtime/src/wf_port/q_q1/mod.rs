//! Chunk q_q1: Rust port of `skills/designer/engine/scripts/lib/impeccable-paths.mjs`.
//!
//! `impeccable-paths.mjs` exports two kinds of functions:
//! 1. Pure path derivation under a project root (`getImpeccableDir`,
//!    `getDesignSidecarPath`, `getLiveDir`, `getLiveConfigPath`,
//!    `getLiveServerPath`, `getLiveSessionsDir`, `getLiveAnnotationsDir`,
//!    `getCritiqueDir`, and their `Legacy` counterparts) — ported in full
//!    below (`paths`), parameterized on an explicit `project_root` since
//!    the source's own root-resolution (`resolveProjectRoot`, from
//!    `../context.mjs`) is a separate, not-yet-ported file outside this
//!    chunk's owned paths (see `full-P8-designer.md`: `scripts/context.mjs`
//!    is listed NOT-PORTED).
//! 2. Filesystem/process-effectful helpers (`readLiveServerInfo`,
//!    `writeLiveServerInfo`, `removeLiveServerInfo`,
//!    `isLiveServerPidReachable`, `resolveLiveConfigPath`,
//!    `resolveDesignSidecarPath`/`getDesignSidecarCandidates`'s
//!    existence-check ordering) — NOT ported here: `isLiveServerPidReachable`
//!    needs to signal an arbitrary OS pid (no process-signaling crate is
//!    pinned in `Cargo.lock` for this crate), and the others build on it or
//!    on `resolveProjectRoot`. Left NOT-STARTED; see the packet report.

pub mod paths;

pub use paths::{
    get_critique_dir, get_design_sidecar_candidates, get_design_sidecar_path,
    get_impeccable_dir, get_legacy_live_annotations_dir, get_legacy_live_config_path,
    get_legacy_live_server_path, get_legacy_live_sessions_dir, get_live_annotations_dir,
    get_live_config_path, get_live_dir, get_live_server_path, get_live_sessions_dir,
    CRITIQUE_DIR, IMPECCABLE_DIR, LIVE_DIR,
};
