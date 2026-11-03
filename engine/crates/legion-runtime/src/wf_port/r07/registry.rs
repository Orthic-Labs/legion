//! Concrete [`AntipatternLookup`] backed by the full `ANTIPATTERNS` table
//! (`wf_port::w2_014::antipatterns`, itself a full port of
//! `registry/antipatterns.mjs`). This closes the gap this module's own
//! (and `wf_port::r05::real_detectors`'s) doc comments recorded: both
//! `finding()`/`filterByProviders()` here and `detectText`/`detectHtml` in
//! `r05` were written against the [`AntipatternLookup`] trait rather than a
//! concrete registry because, at the time those packets landed, the
//! `ANTIPATTERNS` table had not been ported anywhere in this tree yet. It
//! has been since (`w2_014`), so [`RegistryLookup`] is the missing
//! production wiring: `wf_port::r05::real_detectors::RealDetectors`'s `Reg`
//! type parameter and `detect_url`'s `registry` argument are meant to be
//! filled with this (or a fake, in tests) rather than left permanently
//! generic.

use super::findings::{AntipatternLookup, AntipatternRule};
use crate::wf_port::w2_014::antipatterns::{get_antipattern, Severity, GATED_PROVIDERS};

/// Zero-sized [`AntipatternLookup`] reading straight from the static
/// `ANTIPATTERNS` table ported in `w2_014`. Mirrors JS `getAntipattern(id)`
/// (`registry/antipatterns.mjs`) plus the `GATED_PROVIDERS.size` check
/// `filterByProviders` short-circuits on.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegistryLookup;

impl AntipatternLookup for RegistryLookup {
    fn get(&self, id: &str) -> Option<AntipatternRule> {
        let rule = get_antipattern(id)?;
        Some(AntipatternRule {
            name: rule.name.to_string(),
            description: rule.description.to_string(),
            // JS: `rule.severity || 'warning'`.
            severity: match rule.severity {
                Severity::Advisory => "advisory".to_string(),
                Severity::Default => "warning".to_string(),
            },
            gated: rule.gated.map(|g| g.to_string()),
        })
    }

    fn has_gated_providers(&self) -> bool {
        !GATED_PROVIDERS.is_empty()
    }
}
