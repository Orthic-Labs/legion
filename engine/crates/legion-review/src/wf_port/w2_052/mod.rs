//! Chunk w2_052: port of `src/lib/review/{packet.py,providers/}`.
//!
//! As of packet r60, `gemini.py` and `minimax_anthropic.py`'s live HTTP
//! transport is fully wired here (`gemini::call`,
//! `minimax_anthropic::call_with_metadata`, via `gemini::HttpTransport` /
//! `reqwest::blocking`) — see each submodule's doc comment for exactly
//! what ports faithfully.

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
