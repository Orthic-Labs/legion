//! Port of five security packs (chunk wf058, area `src/providers/security`):
//!
//! - `src/providers/security/packs/browser-http.mjs` — a three-rule `createPatternPack`
//!   instance: browser, CORS, cache, proxy, and HTTP protocol controls.
//! - `src/providers/security/packs/business-logic.mjs` — a two-rule `createPatternPack`
//!   instance: workflow invariants, idempotency, and state-transition authority.
//! - `src/providers/security/packs/cicd-automation.mjs` — a three-rule
//!   `createPatternPack` instance: workflow permissions, immutable dependencies, and
//!   untrusted-event execution.
//! - `src/providers/security/packs/credentials.mjs` — a hand-written pack (credential
//!   formats, named secret assignments, private key blocks) that walks every match of
//!   three global regexes per file, not just the first, and additionally exposes a
//!   `credentials.format` `variantStrategies` root-cause/enumerate pair.
//! - `src/providers/security/packs/crypto-data-privacy.mjs` — a three-rule
//!   `createPatternPack` instance: cryptography, identity protocols, data protection,
//!   and privacy.
//!
//! `git grep` over `engine/` for these five packs' rule ids, pack ids, and
//! `createPatternPack` factory found no prior native port, so all five are ported
//! fresh here (matching wf056's finding for the AI security packs in the same
//! directory: `native_providers/security/*` covers a different, unrelated set of
//! native-tool providers — `ast_grep`, `container_iac`, `dependency_osv`, `opengrep`,
//! `secrets` — not these pattern packs).
//!
//! Four of the five packs here are thin `createPatternPack` instances
//! (`src/providers/security/packs/pattern-pack.mjs`): a pure `analyze` function that,
//! for each file with non-empty source text, finds the bound `repository-artifact`
//! entity (if any) and, for every rule whose regex matches the file text, emits one
//! `Observation`. `pattern_pack::analyze` below reproduces that factory once; each of
//! the four pattern packs is a thin module around it with its own `RULES` table taken
//! verbatim from its JS source (same ids, same regex bodies — translated to Rust
//! `regex` syntax where the JS engine's lookahead/lookaround was not available, see
//! `business_logic` below — same claims, same severity/effect defaults).
//!
//! `credentials.mjs` is hand-written and ported as its own module: it loops every
//! match (not just the first) of three global regexes per file, computes a 1-based
//! line number from the byte offset of the match start, and stamps
//! `detectorMetadata.matchDigest` as the **literal** string `sha256:` followed by the
//! first 16 UTF-16 code units of the matched text (JS `String.prototype.slice` is
//! UTF-16-index based) — this is not a call through `contracts.mjs`'s `digest()`
//! function, and is reproduced bit-for-bit as such here, matching a match ASCII in
//! practice. The pack's `variantStrategies['credentials.format'].enumerate` is
//! reproduced as `credentials::enumerate_format_matches` for parity, though nothing in
//! this crate calls it yet.
//!
//! This module is self-contained like wf056: it defines its own minimal
//! `SecurityModel`/`Entity`/`Relation`/`PackContext`/`Observation` types rather than
//! reaching into wf056's (a private module of a sibling chunk), since no shared
//! security-context module was found under this crate at port time.
//!
//! Everything here is pure: no filesystem walk, no model call, no tool execution, no
//! network access — matching every source file's own header comment (or, for the four
//! pattern-pack instances, `pattern-pack.mjs`'s header comment).

use std::collections::BTreeMap;

use regex::Regex;
use serde_json::{json, Value};

// =================================================================================================
// Minimal shared security-model types (mirrors wf056's self-contained subset).
// =================================================================================================

#[derive(Debug, Clone, Default)]
pub struct Entity {
    pub id: String,
    pub kind: String,
    pub name: String,
    /// Free-form attributes (mirrors `entity.attributes`); looked up by key.
    pub attributes: BTreeMap<String, Value>,
    pub evidence_refs: Vec<String>,
}

impl Entity {
    pub fn attr_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).and_then(Value::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct Relation {
    pub kind: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityModel {
    pub entities: Vec<Entity>,
}

/// Mirrors the subset of the JS `context` object every one of these five packs'
/// `analyze(context)` actually reads: `context.files`, `context.readFile(file)`,
/// `context.model.entities`, and (for `credentials.mjs`'s `enumerate`)
/// `context.denominatorDigest`.
pub struct PackContext<'a> {
    pub files: Vec<String>,
    pub source_text: BTreeMap<String, String>,
    pub model: &'a SecurityModel,
    pub relations: &'a [Relation],
    pub denominator_digest: String,
}

impl<'a> PackContext<'a> {
    pub fn read_file(&self, file: &str) -> Option<&str> {
        self.source_text.get(file).map(String::as_str)
    }

    fn find_entity<F: Fn(&Entity) -> bool>(&self, pred: F) -> Option<&Entity> {
        self.model.entities.iter().find(|e| pred(e))
    }

    /// Mirrors `artifactFor(context, file)` from `pattern-pack.mjs`, and the equivalent
    /// inline lookup in `credentials.mjs`'s `analyze`.
    fn artifact_for(&self, file: &str) -> Option<&Entity> {
        self.find_entity(|e| e.kind == "repository-artifact" && e.attr_str("path") == Some(file))
    }
}

/// Mirrors the observation object each pack's `analyze` pushes.
#[derive(Debug, Clone)]
pub struct Observation {
    pub rule_id: String,
    pub candidate_class: String,
    pub claim: String,
    pub severity_hint: String,
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    pub attacker_capabilities: Vec<String>,
    pub effect_kind: String,
    pub effect_action: String,
    pub effect_object: Option<String>,
    pub effect_scope: String,
    pub effect_environment: String,
    pub chain_roles: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub detector_metadata: Value,
    pub uncertainty: Vec<String>,
}

// =================================================================================================
// pattern-pack.mjs: `createPatternPack` factory, reproduced once for all four
// pattern-pack-shaped packs in this chunk.
// =================================================================================================

/// One entry of a pattern pack's `rules` array (the fields the factory actually reads;
/// `preconditions`/`assets`/`trustBoundaryCrossings`/`requiredControls`/
/// `observedControls` are always the factory's own fixed defaults and are not part of
/// `Observation` here, matching wf056's reduction of the same factory).
pub struct PatternRule {
    pub id: &'static str,
    pub pattern: fn(&str) -> bool,
    pub claim: &'static str,
    /// Defaults to `"medium"` in JS (`rule.severityHint ?? 'medium'`); every rule in
    /// this chunk's four packs sets its own value or relies on that default.
    pub severity_hint: &'static str,
    pub effect_kind: &'static str,
    pub effect_action: &'static str,
    pub effect_scope: Option<&'static str>,
    pub chain_roles: &'static [&'static str],
}

const DEFAULT_ATTACKER_CAPABILITY: &str = "control-request-input";
const DEFAULT_UNCERTAINTY: &str =
    "Reachability and compensating controls require independent adjudication.";

/// Mirrors `createPatternPack({ ... }).analyze(context)`.
fn pattern_pack_analyze(ctx: &PackContext, family: &str, rules: &[PatternRule]) -> Vec<Observation> {
    let mut observations = Vec::new();
    for file in &ctx.files {
        let text = match ctx.read_file(file) {
            Some(t) if !t.is_empty() => t,
            _ => continue,
        };
        let artifact = ctx.artifact_for(file);
        for rule in rules {
            if !(rule.pattern)(text) {
                continue;
            }
            let ids: Vec<String> = artifact.map(|e| vec![e.id.clone()]).unwrap_or_default();
            observations.push(Observation {
                rule_id: rule.id.to_string(),
                candidate_class: family.to_string(),
                claim: rule.claim.to_string(),
                severity_hint: rule.severity_hint.to_string(),
                sources: ids.clone(),
                sinks: ids,
                attacker_capabilities: vec![DEFAULT_ATTACKER_CAPABILITY.to_string()],
                effect_kind: rule.effect_kind.to_string(),
                effect_action: rule.effect_action.to_string(),
                effect_object: artifact.map(|e| e.id.clone()),
                effect_scope: rule.effect_scope.unwrap_or(family).to_string(),
                effect_environment: "application".to_string(),
                chain_roles: rule.chain_roles.iter().map(|s| s.to_string()).collect(),
                evidence_refs: artifact.map(|e| e.evidence_refs.clone()).unwrap_or_default(),
                detector_metadata: json!({ "file": file, "patternFamily": family }),
                uncertainty: vec![DEFAULT_UNCERTAINTY.to_string()],
            });
        }
    }
    observations
}

const DEFAULT_CHAIN_ROLES: &[&str] = &["starter", "impact"];

// =================================================================================================
// browser-http.mjs
// =================================================================================================

pub mod browser_http {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "browser-http";

    fn p_cors_wildcard_credentials(t: &str) -> bool {
        Regex::new(r"(?is)Access-Control-Allow-Origin[^\n]*\*[\s\S]{0,200}Access-Control-Allow-Credentials[^\n]*(?:true|1)")
            .unwrap()
            .is_match(t)
    }
    fn p_trust_forwarded_host(t: &str) -> bool {
        Regex::new(r"(?i)(?:x-forwarded-host|x-forwarded-proto|host)\b[^\n]*(?:redirect|callback|absoluteUrl)")
            .unwrap()
            .is_match(t)
    }
    fn p_sensitive_public_cache(t: &str) -> bool {
        Regex::new(r"(?is)Cache-Control[^\n]*(?:public|s-maxage)[\s\S]{0,200}(?:authorization|session|user|account)")
            .unwrap()
            .is_match(t)
    }

    const RULES: &[PatternRule] = &[
        PatternRule {
            id: "http.cors-wildcard-credentials",
            pattern: p_cors_wildcard_credentials,
            claim: "Credentialed cross-origin access may combine with a wildcard origin.",
            severity_hint: "high",
            effect_kind: "control-bypass",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
        PatternRule {
            id: "http.trust-forwarded-host",
            pattern: p_trust_forwarded_host,
            claim: "A forwarded host value may influence a security-sensitive URL.",
            severity_hint: "medium",
            effect_kind: "control-bypass",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
        PatternRule {
            id: "http.sensitive-public-cache",
            pattern: p_sensitive_public_cache,
            claim: "Sensitive response content may be publicly cacheable.",
            severity_hint: "medium",
            effect_kind: "control-bypass",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
    ];

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        pattern_pack_analyze(ctx, CANDIDATE_CLASS, RULES)
    }
}

// =================================================================================================
// business-logic.mjs
// =================================================================================================

pub mod business_logic {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "business-logic";

    /// JS: `/(?:charge|refund|capture|settle)\s*\([^\n]*(?!idempot)/i`. The trailing
    /// `(?!idempot)` is a zero-width negative lookahead that (per JS regex semantics)
    /// matches at essentially every position not immediately followed by literal
    /// `idempot`, so in practice the whole pattern matches any text containing
    /// `charge(`/`refund(`/`capture(`/`settle(` regardless of whether `idempot`
    /// appears anywhere in the file — the lookahead constrains only the character
    /// position right after the call-opening paren, not the rest of the line. The
    /// `regex` crate has no lookahead, so this is reproduced as the equivalent
    /// unconstrained match: does the money-moving call site appear at all.
    fn p_payment_without_idempotency(t: &str) -> bool {
        Regex::new(r"(?i)(?:charge|refund|capture|settle)\s*\(")
            .unwrap()
            .is_match(t)
    }
    fn p_client_controlled_price(t: &str) -> bool {
        Regex::new(r"(?i)(?:price|amount|total)\s*[:=]\s*(?:req|request|body|params)\b")
            .unwrap()
            .is_match(t)
    }

    const RULES: &[PatternRule] = &[
        PatternRule {
            id: "logic.payment-without-idempotency",
            pattern: p_payment_without_idempotency,
            claim: "A money-moving operation has no visible idempotency binding.",
            severity_hint: "medium",
            effect_kind: "integrity-impact",
            effect_action: "duplicate",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
        PatternRule {
            id: "logic.client-controlled-price",
            pattern: p_client_controlled_price,
            claim: "A client-controlled value may determine a transaction amount.",
            severity_hint: "high",
            effect_kind: "integrity-impact",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
    ];

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        pattern_pack_analyze(ctx, CANDIDATE_CLASS, RULES)
    }
}

// =================================================================================================
// cicd-automation.mjs
// =================================================================================================

pub mod cicd_automation {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "cicd-automation";

    fn p_action_unpinned(t: &str) -> bool {
        Regex::new(r"(?i)uses:\s+[\w.-]+/[\w.-]+@(?:v\d+|main|master)\b")
            .unwrap()
            .is_match(t)
    }
    fn p_pull_request_target_write(t: &str) -> bool {
        Regex::new(r"(?is)pull_request_target[\s\S]{0,1200}permissions:[\s\S]{0,400}(?:write-all|contents:\s*write)")
            .unwrap()
            .is_match(t)
    }
    fn p_verifier_bypass(t: &str) -> bool {
        Regex::new(r"(?i)(?:verify|check|audit)[^\n]*\|\|\s*true|continue-on-error:\s*true")
            .unwrap()
            .is_match(t)
    }

    const RULES: &[PatternRule] = &[
        PatternRule {
            id: "cicd.action-unpinned",
            pattern: p_action_unpinned,
            claim: "A third-party workflow action is not pinned to an immutable commit.",
            severity_hint: "medium",
            effect_kind: "code-execution",
            effect_action: "supply-action",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
        PatternRule {
            id: "cicd.pull-request-target-write",
            pattern: p_pull_request_target_write,
            claim: "An untrusted pull-request-target workflow may hold write authority.",
            severity_hint: "high",
            effect_kind: "code-execution",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
        PatternRule {
            id: "cicd.verifier-bypass",
            pattern: p_verifier_bypass,
            claim: "A CI verifier can fail without failing the job.",
            severity_hint: "high",
            effect_kind: "control-bypass",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
    ];

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        pattern_pack_analyze(ctx, CANDIDATE_CLASS, RULES)
    }
}

// =================================================================================================
// crypto-data-privacy.mjs
// =================================================================================================

pub mod crypto_data_privacy {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "crypto-data-privacy";

    fn p_weak_hash_password(t: &str) -> bool {
        Regex::new(r"(?i)(?:md5|sha1)\s*\([^\n]*(?:password|secret|token)")
            .unwrap()
            .is_match(t)
    }
    fn p_static_iv(t: &str) -> bool {
        Regex::new(r#"(?i)(?:iv|nonce)\s*[:=]\s*(?:Buffer\.alloc\([^)]*,\s*0\)|['"][0-9a-f]{8,}['"])"#)
            .unwrap()
            .is_match(t)
    }
    fn p_pii_log(t: &str) -> bool {
        Regex::new(r"(?i)(?:console|logger)\.(?:log|info|debug)\([^\n]*(?:email|phone|address|token|password|ssn)")
            .unwrap()
            .is_match(t)
    }

    const RULES: &[PatternRule] = &[
        PatternRule {
            id: "crypto.weak-hash-password",
            pattern: p_weak_hash_password,
            claim: "A credential may use an unsuitable fast or weak hash.",
            severity_hint: "high",
            effect_kind: "credential-possession",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
        PatternRule {
            id: "crypto.static-iv",
            pattern: p_static_iv,
            claim: "Encryption may reuse a static IV or nonce.",
            severity_hint: "high",
            effect_kind: "confidentiality-impact",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
        PatternRule {
            id: "privacy.pii-log",
            pattern: p_pii_log,
            claim: "Sensitive personal or credential data may be written to logs.",
            severity_hint: "medium",
            effect_kind: "confidentiality-impact",
            effect_action: "bypass",
            effect_scope: None,
            chain_roles: DEFAULT_CHAIN_ROLES,
        },
    ];

    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        pattern_pack_analyze(ctx, CANDIDATE_CLASS, RULES)
    }
}

// =================================================================================================
// credentials.mjs
// =================================================================================================

pub mod credentials {
    use super::*;

    pub const CANDIDATE_CLASS: &str = "credentials";

    struct SecretRule {
        id: &'static str,
        pattern: fn() -> Regex,
        severity_hint: &'static str,
        message: &'static str,
    }

    fn r_format() -> Regex {
        Regex::new(r#"\b(?:AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|sk-[0-9A-Za-z]{20,})\b"#).unwrap()
    }
    fn r_assignment() -> Regex {
        Regex::new(r#"(?i)\b(?:password|secret|token|apiKey|api_key|privateKey)\s*[:=]\s*['"][^'"]{12,}['"]"#)
            .unwrap()
    }
    fn r_private_key() -> Regex {
        Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap()
    }

    const SECRET_PATTERNS: &[SecretRule] = &[
        SecretRule {
            id: "credentials.format",
            pattern: r_format,
            severity_hint: "high",
            message: "Credential-shaped value.",
        },
        SecretRule {
            id: "credentials.assignment",
            pattern: r_assignment,
            severity_hint: "medium",
            message: "Secret-like assignment with a literal value.",
        },
        SecretRule {
            id: "credentials.private-key",
            pattern: r_private_key,
            severity_hint: "high",
            message: "Private key block.",
        },
    ];

    /// Mirrors `text.slice(0, match.index).split('\n').length`: a 1-based line
    /// number, counting UTF-16 code units up to `byte_offset` as JS `slice` would (for
    /// all fixtures in this port the text is ASCII, so the byte and UTF-16 offsets
    /// coincide; this still counts on the string up to the byte offset for
    /// correctness on the ASCII common case).
    fn line_number(text: &str, byte_offset: usize) -> usize {
        text[..byte_offset].matches('\n').count() + 1
    }

    /// Mirrors `` `sha256:${match[0].slice(0, 16)}` ``: a literal prefix, not a call
    /// through `digest()`. JS `String.prototype.slice` indexes by UTF-16 code unit;
    /// this takes the first 16 `char`s, which coincides with JS's first-16-code-units
    /// behavior for any matched text in the BMP (true for every rule's match set:
    /// ASCII key/token literals and PEM header text).
    fn match_digest_literal(matched: &str) -> String {
        let prefix: String = matched.chars().take(16).collect();
        format!("sha256:{prefix}")
    }

    /// Mirrors `analyze(context)`.
    pub fn analyze(ctx: &PackContext) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &ctx.files {
            let text = match ctx.read_file(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let artifact = ctx.artifact_for(file);
            for rule in SECRET_PATTERNS {
                let re = (rule.pattern)();
                for m in re.find_iter(text) {
                    let line = line_number(text, m.start());
                    let ids: Vec<String> = artifact.map(|e| vec![e.id.clone()]).unwrap_or_default();
                    observations.push(Observation {
                        rule_id: rule.id.to_string(),
                        candidate_class: CANDIDATE_CLASS.to_string(),
                        claim: rule.message.to_string(),
                        severity_hint: rule.severity_hint.to_string(),
                        sources: ids,
                        sinks: Vec::new(),
                        attacker_capabilities: vec!["read-repository".to_string()],
                        effect_kind: "knowledge".to_string(),
                        effect_action: "possess".to_string(),
                        effect_object: artifact.map(|e| e.id.clone()),
                        effect_scope: "credential-material".to_string(),
                        effect_environment: "any".to_string(),
                        chain_roles: vec!["starter".to_string(), "enabler".to_string()],
                        evidence_refs: Vec::new(),
                        detector_metadata: json!({
                            "file": file,
                            "line": line,
                            "matchDigest": match_digest_literal(m.as_str()),
                        }),
                        uncertainty: vec![
                            "Whether the value is live and what scope it has is unproven until adjudication."
                                .to_string(),
                        ],
                    });
                }
            }
        }
        observations
    }

    /// One match from `variantStrategies['credentials.format'].enumerate`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CredentialFormatMatch {
        pub file: String,
        pub line: usize,
        pub semantic_fingerprint: String,
        pub disposition: &'static str,
    }

    /// Mirrors `variantStrategies['credentials.format'].enumerate(context, signature)`:
    /// re-scans every one of `context.files` against all three `SECRET_PATTERNS` (not
    /// only `credentials.format`, matching the JS source's own loop, which reuses the
    /// same `SECRET_PATTERNS` table rather than filtering to the `credentials.format`
    /// rule) and returns one match per hit, in `(file, then match order)` order. `rootCause`
    /// is a fixed `{ class: 'credential-in-repository', semanticFeatures: ['credential-shaped-literal'] }`
    /// and is not modeled as a return value here since callers do not need it echoed back.
    pub fn enumerate_format_matches(ctx: &PackContext) -> Vec<CredentialFormatMatch> {
        let mut matches = Vec::new();
        for file in &ctx.files {
            let text = ctx.read_file(file).unwrap_or_default();
            for rule in SECRET_PATTERNS {
                let re = (rule.pattern)();
                for m in re.find_iter(text) {
                    matches.push(CredentialFormatMatch {
                        file: file.clone(),
                        line: line_number(text, m.start()),
                        semantic_fingerprint: format!("sha256:{}", m.as_str()),
                        disposition: "CONFIRMED",
                    });
                }
            }
        }
        matches
    }
}
