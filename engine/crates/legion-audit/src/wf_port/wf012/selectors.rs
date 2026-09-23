//! Faithful port of `src/lib/providers/sdk/selectors.mjs`.
//!
//! ```js
//! export function evaluateSelector(selector = {}, projection = {}) {
//!   const paths = new Set(projection.files ?? []);
//!   return (selector.paths ?? []).every((path) => paths.has(path))
//!     && (selector.extensions ?? []).every((ext) => (projection.parsedExtensions ?? []).includes(ext));
//! }
//! ```
//! Both `selector` and `projection` default to `{}` in JS, and every field is
//! independently optional; the Rust `Default` impls below reproduce that
//! (an all-defaulted selector matches any projection, vacuously).

use std::collections::HashSet;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Selector {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Projection {
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default, rename = "parsedExtensions")]
    pub parsed_extensions: Vec<String>,
}

pub fn evaluate_selector(selector: &Selector, projection: &Projection) -> bool {
    let paths: HashSet<&str> = projection.files.iter().map(String::as_str).collect();
    let paths_match = selector.paths.iter().all(|path| paths.contains(path.as_str()));
    let extensions_match = selector
        .extensions
        .iter()
        .all(|ext| projection.parsed_extensions.iter().any(|p| p == ext));
    paths_match && extensions_match
}
