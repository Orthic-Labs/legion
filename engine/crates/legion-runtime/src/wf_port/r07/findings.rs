//! Port of `finding()` (`detector/findings.mjs`) and `filterByProviders()`
//! (`detector/registry/antipatterns.mjs`), the two pieces of
//! `detect-url.mjs`/`detect-url-cdp.mjs` that shape raw browser findings into
//! the detector's output format.
//!
//! Both JS functions look an antipattern id up in the full `ANTIPATTERNS`
//! registry table (name/description/severity/gated-provider). That table is
//! a large, separate, unported registry file (see the Q0/P8-designer gap
//! notes for `detector/registry/antipatterns.mjs`), so the lookup is
//! abstracted behind [`AntipatternLookup`] here rather than duplicated or
//! blocked on.

use std::collections::HashSet;

/// One antipattern's registry entry, as read by `finding()`/`filterByProviders()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntipatternRule {
    pub name: String,
    pub description: String,
    /// JS default: `rule.severity || 'warning'`.
    pub severity: String,
    /// `rule.gated`: `Some(provider)` if this rule is gated behind a named
    /// provider, `None` (JS: falsy) otherwise.
    pub gated: Option<String>,
}

/// Stands in for `registry/antipatterns.mjs`'s `getAntipattern` (used by
/// `finding()`) and the `GATED_PROVIDERS` set (used by `filterByProviders`).
pub trait AntipatternLookup {
    fn get(&self, id: &str) -> Option<AntipatternRule>;
    /// Mirrors `GATED_PROVIDERS.size`: true iff any registry rule declares a
    /// `gated` provider. `filterByProviders` short-circuits to "keep
    /// everything" when this is empty/false.
    fn has_gated_providers(&self) -> bool;
}

/// One finding as returned by `finding()`. JS: `{ antipattern, name,
/// description, severity, file, line, snippet }`, with `ignoreValue` added
/// ad hoc by the two callers in `detect-url.mjs`/`detect-url-cdp.mjs` when
/// the browser-side result carried one.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub antipattern: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub file: String,
    pub line: u32,
    pub snippet: String,
    pub ignore_value: Option<String>,
}

/// Port of `finding(id, filePath, snippet, line = 0)`. JS calls
/// `getAntipattern(id)` unguarded — a missing id throws (`ap.name` on
/// `undefined`); the port returns `Err` for the same case rather than
/// panicking, since callers can decide how to surface it.
pub fn finding(
    registry: &impl AntipatternLookup,
    id: &str,
    file_path: &str,
    snippet: &str,
) -> Result<Finding, String> {
    finding_at_line(registry, id, file_path, snippet, 0)
}

/// `finding()` with an explicit `line`, matching the JS default parameter.
pub fn finding_at_line(
    registry: &impl AntipatternLookup,
    id: &str,
    file_path: &str,
    snippet: &str,
    line: u32,
) -> Result<Finding, String> {
    let ap = registry
        .get(id)
        .ok_or_else(|| format!("unknown antipattern id: {id}"))?;
    Ok(Finding {
        antipattern: id.to_string(),
        name: ap.name,
        description: ap.description,
        severity: ap.severity,
        file: file_path.to_string(),
        line,
        snippet: snippet.to_string(),
        ignore_value: None,
    })
}

/// Port of `filterByProviders(findings, providers = [])`. Same short-circuit
/// as JS: if the registry has no gated providers at all, every finding
/// passes through untouched (including ones whose id isn't in the
/// registry — JS's `getAntipattern` returning falsy also passes through via
/// `!rule || !rule.gated`).
pub fn filter_by_providers(
    registry: &impl AntipatternLookup,
    findings: Vec<Finding>,
    providers: &[String],
) -> Vec<Finding> {
    if !registry.has_gated_providers() {
        return findings;
    }
    let enabled: HashSet<&str> = providers.iter().map(String::as_str).collect();
    findings
        .into_iter()
        .filter(|f| match registry.get(&f.antipattern) {
            None => true,
            Some(rule) => match rule.gated {
                None => true,
                Some(gate) => enabled.contains(gate.as_str()),
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeRegistry {
        rules: HashMap<String, AntipatternRule>,
        gated_count: usize,
    }

    impl AntipatternLookup for FakeRegistry {
        fn get(&self, id: &str) -> Option<AntipatternRule> {
            self.rules.get(id).cloned()
        }
        fn has_gated_providers(&self) -> bool {
            self.gated_count > 0
        }
    }

    fn registry() -> FakeRegistry {
        let mut rules = HashMap::new();
        rules.insert(
            "low-contrast".to_string(),
            AntipatternRule {
                name: "Low contrast".to_string(),
                description: "text vs background".to_string(),
                severity: "warning".to_string(),
                gated: None,
            },
        );
        rules.insert(
            "ai-slop-gradient".to_string(),
            AntipatternRule {
                name: "AI slop gradient".to_string(),
                description: "generic gradient".to_string(),
                severity: "warning".to_string(),
                gated: Some("openai".to_string()),
            },
        );
        FakeRegistry {
            rules,
            gated_count: 1,
        }
    }

    #[test]
    fn finding_builds_from_registry_with_default_line_zero() {
        let f = finding(&registry(), "low-contrast", "https://x", "snippet").unwrap();
        assert_eq!(f.antipattern, "low-contrast");
        assert_eq!(f.name, "Low contrast");
        assert_eq!(f.file, "https://x");
        assert_eq!(f.line, 0);
        assert_eq!(f.snippet, "snippet");
        assert!(f.ignore_value.is_none());
    }

    #[test]
    fn finding_unknown_id_errors_instead_of_panicking() {
        assert!(finding(&registry(), "nope", "u", "s").is_err());
    }

    #[test]
    fn filter_by_providers_keeps_ungated_and_enabled_gated() {
        let reg = registry();
        let findings = vec![
            finding(&reg, "low-contrast", "u", "s").unwrap(),
            finding(&reg, "ai-slop-gradient", "u", "s").unwrap(),
        ];
        let kept = filter_by_providers(&reg, findings, &["openai".to_string()]);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn filter_by_providers_drops_disabled_gated() {
        let reg = registry();
        let findings = vec![
            finding(&reg, "low-contrast", "u", "s").unwrap(),
            finding(&reg, "ai-slop-gradient", "u", "s").unwrap(),
        ];
        let kept = filter_by_providers(&reg, findings, &[]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].antipattern, "low-contrast");
    }

    #[test]
    fn filter_by_providers_short_circuits_when_registry_has_no_gates() {
        let reg = FakeRegistry {
            rules: HashMap::new(),
            gated_count: 0,
        };
        let findings = vec![Finding {
            antipattern: "whatever".to_string(),
            name: "n".to_string(),
            description: "d".to_string(),
            severity: "warning".to_string(),
            file: "u".to_string(),
            line: 0,
            snippet: "s".to_string(),
            ignore_value: None,
        }];
        let kept = filter_by_providers(&reg, findings, &[]);
        assert_eq!(kept.len(), 1);
    }
}
