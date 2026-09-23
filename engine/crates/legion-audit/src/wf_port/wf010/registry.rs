//! Port of `src/lib/providers/registry.mjs`'s pure `resolve`/`select`
//! methods on the object `loadProviderRegistry` returns.
//!
//! GAP: `loadProviderRegistry` itself reads
//! `src/registry/providers.json` + `src/registry/provider-aliases.json`,
//! JSON-schema-validates each provider against
//! `src/schemas/provider/provider-v2.schema.json`, calls
//! `validateProviderV2`, and — for `runtime-script` providers — reads the
//! module file and checks its digest. `legion-provider-sdk::registry`
//! (`ProviderRegistryDocument`, `ProviderRegistry`) is an existing native
//! provider registry, but it loads a differently-shaped document (its own
//! `implementation_key`/`depends_on` schema, not `providers.json` +
//! `provider-aliases.json`) and does not do alias resolution the way
//! `resolve`/`select` below do, so it is not a drop-in replacement for this
//! file; this port covers only the alias-aware lookup semantics, which a
//! future loader can compose with whatever reads the JSON files.
use std::collections::BTreeMap;

/// Faithful port of `registry.resolve(id)`:
/// `aliases[id] ?? id`, then a required lookup by that canonical id.
pub fn resolve<'a, P>(
    by_id: &'a BTreeMap<String, P>,
    aliases: &BTreeMap<String, String>,
    id: &str,
) -> Result<&'a P, RegistryError> {
    let canonical = aliases.get(id).map(String::as_str).unwrap_or(id);
    by_id
        .get(canonical)
        .ok_or_else(|| RegistryError::UnknownProvider { id: id.to_string() })
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("unknown provider: {id}")]
    UnknownProvider { id: String },
}

/// Faithful port of `registry.select(ids)`:
/// `ids.map(resolve).filter(({selectable}) => selectable !== false)`.
///
/// `is_selectable` stands in for reading `provider.selectable` off the
/// resolved provider (`selectable !== false` keeps a provider whose
/// `selectable` field is `true`, absent/`undefined`, or any other non-`false`
/// value — only an explicit `false` excludes it).
pub fn select<'a, P>(
    by_id: &'a BTreeMap<String, P>,
    aliases: &BTreeMap<String, String>,
    ids: &[String],
    is_selectable: impl Fn(&P) -> bool,
) -> Result<Vec<&'a P>, RegistryError> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let provider = resolve(by_id, aliases, id)?;
        if is_selectable(provider) {
            out.push(provider);
        }
    }
    Ok(out)
}
