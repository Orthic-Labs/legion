//! Port of `src/providers/security/{contracts,candidate-engine,attack-path-synthesis,attack-path-reconcile,evidence-synthesis}.mjs`
//! (chunk wf052).
//!
//! Security artifact contracts (enums, `stableId`/`digest`, binding
//! assertions), the candidate v2 engine, bounded attack-path synthesis
//! (BFS over facts/bridges/objectives), reconciliation of primitive
//! verdicts onto path hypotheses, and final evidence synthesis
//! (findings/proven-paths/root-causes/controls). None of these five files
//! reference Membrane or Blueprint services; `contracts.mjs`'s
//! `blueprintGenerationId`/`blueprintManifestDigest` binding fields name a
//! repository-blueprint *generation id/digest* pinned into the audit plan
//! seal, not a call to the Membrane/Blueprint product — there is no network
//! or service call to drop here.
//!
//! Records are represented as `serde_json::Value` rather than fixed Rust
//! structs, matching the wf011 SDK port's precedent for this same
//! loosely-shaped, `??`/spread-heavy JS artifact style. The workspace
//! `serde_json` has `preserve_order` enabled; `contracts::canonicalize`'s
//! explicit key sort (not map insertion order) is what makes
//! `stable_id`/`digest` match JS `JSON.stringify` byte-for-byte.

pub mod attack_path_reconcile;
pub mod attack_path_synthesis;
pub mod candidate_engine;
pub mod contracts;
pub mod evidence_synthesis;
