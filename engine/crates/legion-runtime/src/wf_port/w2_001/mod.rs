//! Portable W2-001 Alchemist event, runner-input, and Citadel viewer helpers.
//!
//! `parse_events.py` is ported in full: `first_text`, `classify`, BOM
//! stripping, JSONL parsing and the `--summary` report format all have
//! direct Rust equivalents below, with unit tests mirroring the Python
//! module's own behaviour (see `parse_events`).
//!
//! `parse_events` classifies JSONL events; `worker_launch` validates native
//! runner inputs; `stack_status` exposes Citadel URL and tray text helpers.
//!

pub mod parse_events;
pub mod stack_status;
pub mod worker_launch;
