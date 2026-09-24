//! The native provider that runs variant analysis over every pack whose
//! `variantStrategies` has been ported to Rust: aggregates
//! `wf060::{injection, http_protocol_cache, ics_ot}`,
//! `wf063::{supply_chain, uploads}`, and
//! `r66::{ai_prompt_injection, authorization_tenant, browser_client}`
//! behind [`variant_analysis::PackByProvider`], so
//! `variant_analysis::analyze_variants` (the port of
//! `src/providers/security/variant-analysis.mjs`) can be run natively
//! instead of only through a `reasoning-contract` runner.
//!
//! Each pack's ported `variant_root_cause`/`variant_enumerate` (or, for
//! `injection.mjs`, `root_cause`/`enumerate`) functions were written to take
//! that pack's own chunk-local `Context` (files + `readFile`), exactly
//! mirroring `analyze(context)`'s parameter. In the JS source, the object
//! `variant-analysis.mjs` passes as `enumerate`'s first argument is named
//! `model`, but every pack's `buildVariantStrategy(rule).enumerate(context)`
//! reads `context.files`/`context.readFile(...)` directly off it — i.e. in
//! production the `model` object passed in *is* the same repository
//! file-context `analyze()` was given, just referred to by a different
//! parameter name at the call site. This registry reproduces that: each
//! [`PackStrategy`] closes over a reference to the live chunk-local
//! `Context` (constructed once per run, same as for `analyze()`) rather than
//! reading it back out of the [`Value`] `model` argument
//! `VariantStrategy::enumerate` receives, which callers still pass through
//! unread here (kept only for trait-signature fidelity with the JS call
//! shape `variant-analysis.mjs` uses).

use std::collections::HashMap;

use serde_json::Value;

use super::variant_analysis::{PackByProvider, VariantStrategy};
use crate::wf_port::r66;
use crate::wf_port::wf060;
use serde_json::json;

/// `wf060::injection::{RootCause, VariantStrategyResult}` derive a plain
/// `serde::Serialize` with no `rename_all`, so `serde_json::to_value` would
/// emit their Rust field names verbatim (`sink_class`, `coverage_gaps`,
/// ...). Every other pack ported in this registry builds its
/// `variantStrategies` result with explicit camelCase JSON keys (matching
/// the JS `enumerate()`/`rootCause()` object shape the engine in
/// `variant_analysis.rs` reads via `.get("coverageGaps")` etc.), so these
/// two adapters translate `injection.rs`'s typed structs into that same
/// camelCase shape instead of round-tripping through the derived
/// `Serialize` impl.
fn injection_root_cause_to_value(r: wf060::injection::RootCause) -> Value {
    json!({
        "class": r.class,
        "sinkClass": r.sink_class,
        "sinkKind": r.sink_kind,
        "missingControl": r.missing_control,
        "semanticFeatures": r.semantic_features,
    })
}

fn injection_enumerate_to_value(r: wf060::injection::VariantStrategyResult) -> Value {
    json!({
        "denominator": {
            "kind": r.denominator.kind,
            "digest": r.denominator.digest,
            "expected": r.denominator.expected,
            "examined": r.denominator.examined,
            "unexamined": r.denominator.unexamined,
        },
        "strategies": r.strategies.into_iter().map(|s| json!({
            "id": s.id,
            "kind": s.kind,
            "description": s.description,
            "queryDigest": s.query_digest,
            "complete": s.complete,
            "coverageGaps": s.coverage_gaps,
        })).collect::<Vec<_>>(),
        "matches": r.matches.into_iter().map(|m| json!({
            "file": m.file,
            "line": m.line,
            "semanticFingerprint": m.semantic_fingerprint,
            "disposition": m.disposition,
        })).collect::<Vec<_>>(),
        "coverageGaps": r.coverage_gaps,
    })
}

/// One rule's `variantStrategies` entry, implemented by delegating to the
/// pack module's own ported `root_cause`/`enumerate` (or
/// `variant_root_cause`/`variant_enumerate`) functions, closed over via
/// plain function pointers/closures so every pack can share one adapter
/// type regardless of its chunk-local `Context` type.
pub struct PackStrategy<'a> {
    root_cause_fn: Box<dyn Fn(&Value) -> Option<Value> + 'a>,
    enumerate_fn: Box<dyn Fn() -> Option<Value> + 'a>,
}

impl<'a> VariantStrategy for PackStrategy<'a> {
    fn root_cause(&self, candidate: &Value, _verdict: &Value) -> Value {
        (self.root_cause_fn)(candidate).unwrap_or(Value::Null)
    }

    fn enumerate(
        &self,
        _plan: &Value,
        _model: &Value,
        _candidate: &Value,
        _verdict: &Value,
        _binding: &Value,
        _root_cause_signature: &Value,
    ) -> Value {
        (self.enumerate_fn)().unwrap_or(Value::Null)
    }
}

/// Aggregates every ported pack's per-rule [`PackStrategy`] behind
/// [`PackByProvider`], keyed exactly like the JS `packByProvider` map's
/// `pack.variantStrategies[candidate.ruleId]` lookup: outer key is the
/// pack's provider id, inner key is the rule id.
#[derive(Default)]
pub struct PackRegistry<'a> {
    strategies: HashMap<(String, String), PackStrategy<'a>>,
}

impl<'a> PackRegistry<'a> {
    pub fn new() -> Self {
        Self { strategies: HashMap::new() }
    }

    fn insert(&mut self, provider: &str, rule_id: &'static str, strategy: PackStrategy<'a>) {
        self.strategies.insert((provider.to_string(), rule_id.to_string()), strategy);
    }

    /// Registers every `security.injection` rule's strategy
    /// (`wf060::injection::{root_cause, enumerate}`).
    pub fn with_injection(mut self, context: &'a wf060::common::Context) -> Self {
        for rule_id in wf060::injection::rule_ids() {
            let ctx = context;
            self.insert(
                wf060::injection::ID,
                rule_id,
                PackStrategy {
                    root_cause_fn: Box::new(move |candidate: &Value| {
                        let sink_engine = candidate
                            .get("detectorMetadata")
                            .and_then(|d| d.get("sinkEngine"))
                            .and_then(Value::as_str);
                        wf060::injection::root_cause(rule_id, sink_engine).map(injection_root_cause_to_value)
                    }),
                    enumerate_fn: Box::new(move || {
                        wf060::injection::enumerate(ctx, rule_id).map(injection_enumerate_to_value)
                    }),
                },
            );
        }
        self
    }

    /// Registers `security.http-protocol-cache`'s three strategy rules.
    pub fn with_http_protocol_cache(mut self, context: &'a wf060::common::Context) -> Self {
        for rule_id in ["hsts.missing", "cache.sensitive-content-cacheable", "proxy.trust-misconfigured"] {
            let ctx = context;
            self.insert(
                wf060::http_protocol_cache::ID,
                rule_id,
                PackStrategy {
                    root_cause_fn: Box::new(move |_candidate: &Value| wf060::http_protocol_cache::variant_root_cause(rule_id)),
                    enumerate_fn: Box::new(move || wf060::http_protocol_cache::variant_enumerate(ctx, rule_id)),
                },
            );
        }
        self
    }

    /// Registers every `security.ics-ot` rule's strategy.
    pub fn with_ics_ot(mut self, context: &'a wf060::common::Context) -> Self {
        for rule_id in wf060::ics_ot::rule_ids() {
            let ctx = context;
            self.insert(
                wf060::ics_ot::ID,
                rule_id,
                PackStrategy {
                    root_cause_fn: Box::new(move |candidate: &Value| {
                        let file = candidate.get("detectorMetadata").and_then(|d| d.get("file")).and_then(Value::as_str);
                        wf060::ics_ot::variant_root_cause(rule_id, file)
                    }),
                    enumerate_fn: Box::new(move || wf060::ics_ot::variant_enumerate(ctx, rule_id)),
                },
            );
        }
        self
    }

    /// Registers every `security.supply-chain` rule's strategy.
    pub fn with_supply_chain(mut self, context: &'a super::common::Context) -> Self {
        for rule_id in super::supply_chain::rule_ids() {
            let ctx = context;
            self.insert(
                super::supply_chain::ID,
                rule_id,
                PackStrategy {
                    root_cause_fn: Box::new(move |_candidate: &Value| super::supply_chain::variant_root_cause(rule_id)),
                    enumerate_fn: Box::new(move || super::supply_chain::variant_enumerate(ctx, rule_id)),
                },
            );
        }
        self
    }

    /// Registers every `security.uploads` rule's strategy.
    pub fn with_uploads(mut self, context: &'a super::common::Context) -> Self {
        for rule_id in super::uploads::rule_ids() {
            let ctx = context;
            self.insert(
                super::uploads::ID,
                rule_id,
                PackStrategy {
                    root_cause_fn: Box::new(move |candidate: &Value| {
                        let sink_api = candidate.get("detectorMetadata").and_then(|d| d.get("sinkApi")).and_then(Value::as_str);
                        super::uploads::variant_root_cause(rule_id, sink_api)
                    }),
                    enumerate_fn: Box::new(move || super::uploads::variant_enumerate(ctx, rule_id)),
                },
            );
        }
        self
    }

    /// Registers every `security.ai-prompt-injection` rule's strategy.
    pub fn with_ai_prompt_injection(mut self, context: &'a r66::Context) -> Self {
        for rule_id in r66::ai_prompt_injection::rule_ids() {
            let ctx = context;
            self.insert(
                r66::ai_prompt_injection::ID,
                rule_id,
                PackStrategy {
                    root_cause_fn: Box::new(move |candidate: &Value| {
                        let sink = candidate.get("detectorMetadata").and_then(|d| d.get("sink")).and_then(Value::as_str);
                        r66::ai_prompt_injection::variant_root_cause(rule_id, sink)
                    }),
                    enumerate_fn: Box::new(move || r66::ai_prompt_injection::variant_enumerate(ctx, rule_id)),
                },
            );
        }
        self
    }

    /// Registers `security.authorization-tenant`'s one strategy rule.
    pub fn with_authorization_tenant(mut self, context: &'a r66::Context) -> Self {
        let rule_id = "authorization.object-write.missing-owner-check";
        let ctx = context;
        self.insert(
            r66::authorization_tenant::ID,
            rule_id,
            PackStrategy {
                root_cause_fn: Box::new(move |candidate: &Value| {
                    let source_kind = candidate.get("detectorMetadata").and_then(|d| d.get("sourceKind")).and_then(Value::as_str);
                    let sink_kind = candidate.get("detectorMetadata").and_then(|d| d.get("sinkKind")).and_then(Value::as_str);
                    r66::authorization_tenant::variant_root_cause(rule_id, source_kind, sink_kind)
                }),
                enumerate_fn: Box::new(move || r66::authorization_tenant::variant_enumerate(ctx, rule_id)),
            },
        );
        self
    }

    /// Registers `security.browser-client`'s three strategy rules.
    pub fn with_browser_client(mut self, context: &'a r66::Context) -> Self {
        for rule_id in [
            "csrf.state-changing-route.missing-token",
            "cors.wildcard-origin-with-credentials",
            "oauth.redirect-uri.unvalidated",
        ] {
            let ctx = context;
            self.insert(
                r66::browser_client::ID,
                rule_id,
                PackStrategy {
                    root_cause_fn: Box::new(move |_candidate: &Value| r66::browser_client::variant_root_cause(rule_id)),
                    enumerate_fn: Box::new(move || r66::browser_client::variant_enumerate(ctx, rule_id)),
                },
            );
        }
        self
    }
}

impl<'a> PackByProvider for PackRegistry<'a> {
    fn strategy_for(&self, provider: &str, rule_id: &str) -> Option<&dyn VariantStrategy> {
        self.strategies
            .get(&(provider.to_string(), rule_id.to_string()))
            .map(|s| s as &dyn VariantStrategy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_a_registered_supply_chain_rule() {
        let ctx = crate::wf_port::wf063::common::Context::new().with_file("package.json", "{}");
        let registry = PackRegistry::new().with_supply_chain(&ctx);
        assert!(registry.strategy_for("security.supply-chain", "supply-chain.lockfile.missing").is_some());
    }

    #[test]
    fn unregistered_provider_resolves_to_none() {
        let registry = PackRegistry::new();
        assert!(registry.strategy_for("security.unknown", "some.rule").is_none());
    }

    #[test]
    fn ics_ot_enumerate_never_reports_matches_mirroring_the_js_source() {
        let ctx = wf060::common::Context::new().with_file("plc.py", "client.writeCoil(1, true)");
        let registry = PackRegistry::new().with_ics_ot(&ctx);
        let strategy = registry.strategy_for("security.ics-ot", "ics-ot.authorization.unauthenticated-write-command").unwrap();
        let result = strategy.enumerate(&Value::Null, &Value::Null, &Value::Null, &Value::Null, &Value::Null, &Value::Null);
        assert_eq!(result["matches"].as_array().unwrap().len(), 0);
    }
}
