//! Packet P11c — providers/{visual, ux, safety, performance} family. Faithful
//! Rust ports of `src/providers/{visual/**,visual-core.mjs,ux/**,safety/**,
//! performance/**}` (see `full-P11c.md` for the packet table).
//!
//! `visual_core` also carries a small self-contained zlib/DEFLATE codec: the
//! crate has no image/compression dependency, and the JS source's own PNG
//! encoder/decoder is itself dependency-free (Node's `node:zlib`), so this
//! keeps the port at parity rather than adding a new external dependency.

pub mod performance;
pub mod safety;
pub mod ux;
pub mod visual;
pub mod visual_core;
