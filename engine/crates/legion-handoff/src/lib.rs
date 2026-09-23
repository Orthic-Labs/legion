#![forbid(unsafe_code)]

pub mod builder;
pub mod error;
pub mod model;
pub mod receipt;
pub mod source;
pub mod token;
pub mod l1_port;
pub mod l1b_port;

pub use builder::HandoffBuilder;
pub use error::{HandoffError, Result, SourceError, SourceErrorCode};
pub use model::{HandoffEntry, HandoffPacket, HandoffSection, Omission};
pub use receipt::HandoffReceipt;
pub use source::{
    ArtifactReader, EventCursor, EventPage, HandoffQuery, MemorySearch, Record, RecordCategory,
    RecordKind, RecordSource, SessionEventReader, SourceSet,
};
pub use token::{CharTokenizer, TiktokenTokenizer, TokenAccounting, TokenBudget, Tokenizer};
