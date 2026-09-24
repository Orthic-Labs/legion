//! Packet U02: port of `src/lib/artifacts/run-store.mjs`.
//!
//! `run-store.mjs` exports one class, `RunArtifactStore`: a durable,
//! content-addressed artifact store rooted at a directory. It is live —
//! `src/lib/core/audit.mjs` and `src/lib/core/index.mjs` both import
//! `RunArtifactStore`, and `tests/artifact-store.test.mjs` exercises it
//! directly — but `wf_port::w2_039`/`wf_port::w2_040` both explicitly
//! record it as living outside their chunks ("a stateful class this chunk
//! does not port"). This module closes that gap.
//!
//! Ported in full: `constructor` (path resolution), `init` (create the root
//! directory, mode 0o700), `writeJson` (pretty-print + trailing newline,
//! delegates to `writeBytes` with `mediaType: "application/json"`),
//! `writeBytes` (path-escape guard, write-to-temp + fsync + atomic rename,
//! re-read the written bytes to compute a `sha256:<hex>` digest, register an
//! immutable record keyed by the root-relative POSIX path), `records`
//! (path-sorted snapshot), and `readVerified` (read-back digest check
//! against the registered record).
//!
//! Filesystem access is behind the [`ArtifactFs`] trait so tests do not
//! touch a real filesystem; [`StdFs`] is the production implementation.

pub mod store;

pub use store::{ArtifactFs, ArtifactRecord, RunArtifactStore, StdFs, WriteBytesSpec, WriteJsonSpec};
