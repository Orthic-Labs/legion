//! Shared canonicalization/digest helpers used identically by
//! `effect-graph.mjs` and `mechanical.mjs` (each file defines its own private
//! copy in JS; this is one faithful shared implementation).
//!
//! ```js
//! function canonical(value) {
//!   if (Array.isArray(value)) return value.map(canonical);
//!   if (value && typeof value === 'object') {
//!     return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
//!   }
//!   return value;
//! }
//! function digestOf(namespace, value) {
//!   return `sha256:${createHash('sha256').update(`${namespace}\0${JSON.stringify(canonical(value))}`).digest('hex')}`;
//! }
//! ```

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn canonical(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonical(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub fn digest_of(namespace: &str, value: &Value) -> String {
    let canon = canonical(value);
    let json_text = serde_json::to_string(&canon).expect("Value serialization cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0u8]);
    hasher.update(json_text.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Faithful port of the module-private `digest` helper in `fix-contract.mjs`,
/// which — unlike the two helpers above — does NOT canonicalize (no key
/// sort): `` `sha256:${createHash('sha256').update(JSON.stringify(body)).digest('hex')}` ``.
/// Relies on `serde_json`'s workspace-wide `preserve_order` feature so
/// `serde_json::to_string` reproduces the JS `JSON.stringify` insertion-order
/// key sequence for a `Value` built with the same field order as the JS
/// object literal.
pub fn digest_uncanonicalized(value: &Value) -> String {
    let json_text = serde_json::to_string(value).expect("Value serialization cannot fail");
    let hash = Sha256::digest(json_text.as_bytes());
    format!("sha256:{}", hex::encode(hash))
}

/// `[...new Set(values ?? [])].sort()` — dedupe then lexicographic string sort.
pub fn sorted_unique_strings<I: IntoIterator<Item = String>>(values: I) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for v in values {
        set.insert(v);
    }
    set.into_iter().collect()
}

/// `[...arr].sort()` on strings — no dedupe, just a stable lexicographic sort.
pub fn sorted_strings(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

/// Faithful port of the glob-to-regex translation shared by
/// `effect-graph.mjs`'s `matchesPath` and `reasoning-packets.mjs`'s
/// `matchesGlob`:
/// ```js
/// const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, ' ').replace(/\*/g, '[^/]*').replace(/ /g, '.*');
/// return new RegExp(`^${escaped}$`).test(path);
/// ```
pub fn matches_glob(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }
    let mut escaped = String::new();
    for ch in pattern.chars() {
        if ".+^${}()|[]\\".contains(ch) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    // Mirrors the JS placeholder-swap order exactly, space-as-placeholder
    // included: `**` -> ' ', then `*` -> `[^/]*`, then every remaining space
    // (both the `**` placeholders and any literal space in the pattern) -> `.*`.
    let escaped = escaped.replace("**", " ");
    let escaped = escaped.replace('*', "[^/]*");
    let escaped = escaped.replace(' ', ".*");
    let re = regex::Regex::new(&format!("^{escaped}$")).unwrap_or_else(|_| regex::Regex::new("^$unmatchable^$").unwrap());
    re.is_match(path)
}
