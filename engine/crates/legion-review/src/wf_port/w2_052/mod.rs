//! Chunk w2_052: port of `src/lib/review/{packet.py,providers/}`.
//!
//! See each submodule's doc comment for what ported faithfully vs. what
//! stayed on the Python side (live HTTP transport — no client dependency
//! is added in this chunk; see the chunk report for the `Cargo.toml`
//! patch needed to wire it).

pub mod base;
pub mod gemini;
pub mod minimax_anthropic;
pub mod packet;
pub mod registry;

pub use base::{JurorResult, ProviderError, ProviderImage};
pub use packet::{
    extract_packet, render_packet_skeleton, validate_packet, PacketValidation,
    NO_PACKET_FENCE, PACKET_REQUIRED_SECTIONS, SKELETON_TEMPLATE,
};
