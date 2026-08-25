#![forbid(unsafe_code)]

pub mod catalog;
pub mod discovery;
pub mod error;
pub mod frontmatter;
pub mod projection;

pub use catalog::{
    normalize_path, Catalog, CatalogEntry, CatalogKind, CompactCatalog, CompactCatalogEntry,
};
pub use discovery::{discover, discover_paths, load_compact};
pub use error::{CatalogError, FailureCode};
pub use frontmatter::{
    hex_digest, parse, parse as parse_frontmatter, parse_agent,
    parse_agent as parse_agent_definition, source_hash, AgentFrontmatter, FrontmatterDocument,
};
pub use projection::{canonical_bytes, project, HostProjection, ProjectionRequest};
/// JSON support is re-exported for native crates that consume catalog-owned
/// generated artifacts without adding an independent parser dependency.
pub use serde_json as json;
