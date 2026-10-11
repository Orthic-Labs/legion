//! Packet P11c — providers/{visual, ux, safety} family. Retained Rust ports
//! of `src/providers/{visual/**,visual-core.mjs,ux/**,safety/**}`. Items with
//! no production caller that were reachable only from tests were removed in
//! the native-provider sweep; `performance` was removed with its test.

pub mod safety;
pub mod ux;
pub mod visual;
pub mod visual_core;
