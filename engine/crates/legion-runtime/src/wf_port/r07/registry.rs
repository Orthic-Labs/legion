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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_known_rule() {
        let reg = RegistryLookup;
        let rule = reg.get("side-tab").expect("side-tab is a real rule");
        assert_eq!(rule.name, "Side-tab accent border");
        assert_eq!(rule.severity, "warning");
        assert_eq!(rule.gated, None);
    }

    #[test]
    fn unknown_rule_is_none() {
        let reg = RegistryLookup;
        assert!(reg.get("not-a-real-rule").is_none());
    }

    #[test]
    fn advisory_severity_passes_through() {
        let reg = RegistryLookup;
        let rule = reg.get("design-system-color").expect("known advisory rule");
        assert_eq!(rule.severity, "advisory");
    }

    #[test]
    fn gated_rule_reports_its_provider() {
        let reg = RegistryLookup;
        let rule = reg
            .get("gpt-thin-border-wide-shadow")
            .expect("known gpt-gated rule");
        assert_eq!(rule.gated.as_deref(), Some("gpt"));
    }

    #[test]
    fn has_gated_providers_is_true() {
        assert!(RegistryLookup.has_gated_providers());
    }

    #[test]
    fn finding_uses_registry_lookup() {
        let reg = RegistryLookup;
        let f = super::super::findings::finding_at_line(
            &reg,
            "side-tab",
            "app.css",
            "border: 4px solid red",
            12,
        )
        .expect("side-tab resolves");
        assert_eq!(f.antipattern, "side-tab");
        assert_eq!(f.name, "Side-tab accent border");
        assert_eq!(f.severity, "warning");
        assert_eq!(f.line, 12);
    }
}
