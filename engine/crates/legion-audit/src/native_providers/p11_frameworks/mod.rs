//! Packet P11 — providers/frameworks family. Faithful Rust ports of the
//! small, self-contained JS provider analyzers under `src/providers/**`
//! whose logic does not already live in `native_providers::architecture`.
//!
//! Ports covered here (see `full-P11.md` for the complete packet table):
//! data-integrity, privacy, i18n/locale-map, narrative/{continuity,model},
//! copy/{core,terminology}, licenses, monorepo, systems/custom-grammar,
//! sbom, trust-safety/deceptive-design, generic, codeql,
//! discoverability, governance, provenance, reliability/runtime.
//!
//! `frameworks/{backend,frontend,data}` and `compatibility`/`requirements`
//! are already ported under `native_providers::architecture` — not
//! duplicated here.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::architecture::{common::truthy, evidence};

fn stable_id(namespace: &str, value: &Value) -> String {
    let body = serde_json::to_string(value).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0u8]);
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------
// data-integrity/index.mjs :: integrityFacts
// ---------------------------------------------------------------------
pub mod data_integrity {
    use super::*;

    pub fn integrity_facts(operations: &[Value]) -> Vec<Value> {
        operations
            .iter()
            .map(|operation| {
                serde_json::json!({
                    "operation": operation,
                    "kind": "integrity",
                    "evidenceRequired": true,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------
// privacy/index.mjs :: privacyFacts
// ---------------------------------------------------------------------
pub mod privacy {
    use super::*;

    pub fn privacy_facts(records: &[Value]) -> Vec<Value> {
        records
            .iter()
            .map(|record| {
                let mut object = record.as_object().cloned().unwrap_or_default();
                object.insert("kind".into(), Value::String("privacy".into()));
                object.insert("legalConclusion".into(), Value::Bool(false));
                Value::Object(object)
            })
            .collect()
    }
}

// ---------------------------------------------------------------------
// i18n/locale-map.mjs :: buildLocaleMap
// ---------------------------------------------------------------------
pub mod i18n {
    use super::*;

    pub fn build_locale_map(input: &Value) -> Value {
        let default_locale = input.get("defaultLocale").cloned().unwrap_or(Value::Null);
        let locales: Vec<Value> = input
            .get("locales")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let surfaces: Vec<Value> = input
            .get("surfaces")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut missing = Vec::new();
        for surface in &surfaces {
            let surface_locales: Vec<&Value> = surface
                .get("locales")
                .and_then(Value::as_array)
                .map(|items| items.iter().collect())
                .unwrap_or_default();
            let surface_id = surface.get("id").cloned().unwrap_or(Value::Null);
            for locale in &locales {
                if !surface_locales.contains(&locale) {
                    missing.push(serde_json::json!({
                        "surfaceId": surface_id,
                        "locale": locale,
                    }));
                }
            }
        }
        let status = if missing.is_empty() { "pass" } else { "partial" };
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-locale-map",
            "defaultLocale": default_locale,
            "locales": locales,
            "missing": missing,
            "status": status,
        })
    }
}

// ---------------------------------------------------------------------
// narrative/model.mjs, narrative/continuity.mjs
// ---------------------------------------------------------------------
pub mod narrative {
    use super::*;

    pub fn build_narrative_model(items: &[Value]) -> Value {
        let units: Vec<Value> = items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                serde_json::json!({
                    "id": item.get("id").cloned().unwrap_or(Value::Null),
                    "order": index,
                    "text": item.get("text").cloned().unwrap_or(Value::Null),
                    "claimRefs": item.get("claimRefs").cloned().unwrap_or(Value::Array(vec![])),
                    "purpose": item.get("purpose").cloned().unwrap_or(Value::Null),
                })
            })
            .collect();
        let complete = units.iter().all(|unit| {
            truthy(unit.get("id")) && truthy(unit.get("text"))
        });
        let coverage_gaps: Vec<Value> = units
            .iter()
            .filter(|unit| !truthy(unit.get("purpose")))
            .map(|unit| {
                Value::String(format!(
                    "purpose-missing:{}",
                    unit.get("id").and_then(Value::as_str).unwrap_or_default()
                ))
            })
            .collect();
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-narrative-model",
            "units": units,
            "complete": complete,
            "coverageGaps": coverage_gaps,
        })
    }

    pub fn assess_continuity(model: &Value) -> Value {
        let units: Vec<Value> = model
            .get("units")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut findings = Vec::new();
        for index in 1..units.len() {
            let text_empty = units[index]
                .get("text")
                .and_then(Value::as_str)
                .map(|text| text.trim().is_empty())
                .unwrap_or(true);
            if text_empty {
                findings.push(serde_json::json!({
                    "ruleId": "narrative.empty-unit",
                    "id": units[index].get("id").cloned().unwrap_or(Value::Null),
                }));
            }
        }
        let complete_false = model.get("complete") == Some(&Value::Bool(false));
        let status = if complete_false {
            "unproven"
        } else if !findings.is_empty() {
            "candidates"
        } else {
            "pass"
        };
        let coverage_gaps = model
            .get("coverageGaps")
            .cloned()
            .unwrap_or(Value::Array(vec![]));
        serde_json::json!({
            "schemaVersion": 1,
            "provider": "narrative.continuity",
            "status": status,
            "findings": findings,
            "coverageGaps": coverage_gaps,
        })
    }
}

// ---------------------------------------------------------------------
// copy/core.mjs :: copyFacts, copy/terminology.mjs :: checkTerminology
// ---------------------------------------------------------------------
pub mod copy {
    use super::*;

    pub fn copy_facts(items: &[Value], limits: &Value) -> Value {
        let mut findings = Vec::new();
        let mut facts = Vec::new();
        for item in items {
            let text = item.get("text").and_then(Value::as_str).unwrap_or("");
            let chars = text.chars().count();
            let trimmed = text.trim();
            let words = if trimmed.is_empty() {
                0
            } else {
                trimmed.split_whitespace().count()
            };
            let surface_type = item
                .get("surface")
                .and_then(|surface| surface.get("type"))
                .and_then(Value::as_str);
            let limit = surface_type.and_then(|surface_type| limits.get(surface_type));
            let id = item.get("id").cloned().unwrap_or(Value::Null);
            if trimmed.is_empty() {
                findings.push(serde_json::json!({ "ruleId": "copy.empty", "id": id }));
            }
            if text.contains("{{") || text.contains("${") {
                findings.push(
                    serde_json::json!({ "ruleId": "copy.unresolved-interpolation", "id": id }),
                );
            }
            if let Some(limit_value) = limit.and_then(Value::as_u64) {
                if chars as u64 > limit_value {
                    findings.push(serde_json::json!({
                        "ruleId": "copy.hard-limit",
                        "id": id,
                        "actual": chars,
                        "limit": limit_value,
                    }));
                }
            }
            facts.push(serde_json::json!({ "id": id, "chars": chars, "words": words }));
        }
        let status = if findings.is_empty() { "pass" } else { "candidates" };
        serde_json::json!({
            "schemaVersion": 1,
            "provider": "copy.core",
            "status": status,
            "facts": facts,
            "findings": findings,
            "complete": true,
            "coverageGaps": Value::Array(vec![]),
        })
    }

    pub fn check_terminology(items: &[Value], context: &Value) -> Value {
        let mut findings = Vec::new();
        let terms: Vec<Value> = context
            .get("terms")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let authoritative = context.get("authoritative") == Some(&Value::Bool(true));
        for item in items {
            let text = item.get("text").and_then(Value::as_str).unwrap_or("");
            let id = item.get("id").cloned().unwrap_or(Value::Null);
            for term in &terms {
                let canonical = term.get("canonical").and_then(Value::as_str).unwrap_or("");
                let aliases: Vec<&str> = term
                    .get("aliases")
                    .and_then(Value::as_array)
                    .map(|items| items.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                for alias in aliases {
                    if alias == canonical {
                        continue;
                    }
                    if word_boundary_match_ci(text, alias) {
                        findings.push(serde_json::json!({
                            "ruleId": "copy.terminology-alias",
                            "id": id,
                            "alias": alias,
                            "canonical": canonical,
                        }));
                    }
                }
            }
        }
        let status = if authoritative {
            if findings.is_empty() { "pass" } else { "candidates" }
        } else {
            "unproven"
        };
        let coverage_gaps: Vec<Value> = if authoritative {
            vec![]
        } else {
            vec![Value::String("voice-context-missing".into())]
        };
        serde_json::json!({
            "provider": "copy.terminology",
            "status": status,
            "findings": findings,
            "coverageGaps": coverage_gaps,
        })
    }

    /// Case-insensitive `\balias\b` regex match, ported without pulling in
    /// the `regex` crate for a single-purpose word-boundary test.
    fn word_boundary_match_ci(text: &str, alias: &str) -> bool {
        if alias.is_empty() {
            return false;
        }
        let text_lower = text.to_lowercase();
        let alias_lower = alias.to_lowercase();
        let is_word_byte = |c: char| c.is_alphanumeric() || c == '_';
        let mut start = 0;
        while let Some(offset) = text_lower[start..].find(&alias_lower) {
            let match_start = start + offset;
            let match_end = match_start + alias_lower.len();
            let before_ok = text_lower[..match_start]
                .chars()
                .next_back()
                .map(|c| !is_word_byte(c))
                .unwrap_or(true);
            let after_ok = text_lower[match_end..]
                .chars()
                .next()
                .map(|c| !is_word_byte(c))
                .unwrap_or(true);
            if before_ok && after_ok {
                return true;
            }
            start = match_start + alias_lower.len().max(1);
            if start >= text_lower.len() {
                break;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------
// licenses/index.mjs :: normalizeLicense, policyResult
// ---------------------------------------------------------------------
pub mod licenses {
    use super::*;

    pub fn normalize_license(input: &Value) -> Value {
        let detected = input.get("detected").cloned().unwrap_or(Value::Null);
        let declared = input.get("declared").cloned().unwrap_or(Value::Null);
        let status = if truthy(Some(&detected)) || truthy(Some(&declared)) {
            "known"
        } else {
            "unknown"
        };
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-license-record",
            "package": {
                "name": input.get("name").cloned().unwrap_or(Value::Null),
                "version": input.get("version").cloned().unwrap_or(Value::Null),
            },
            "detected": detected,
            "declared": declared,
            "status": status,
            "path": input.get("path").cloned().unwrap_or(Value::Null),
        })
    }

    pub fn policy_result(records: &[Value], policy: &Value) -> Value {
        let unknown: Vec<Value> = records
            .iter()
            .filter(|record| record.get("status").and_then(Value::as_str) == Some("unknown"))
            .cloned()
            .collect();
        let allow: Vec<&str> = policy
            .get("allow")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let blocked: Vec<Value> = if allow.is_empty() {
            vec![]
        } else {
            records
                .iter()
                .filter(|record| {
                    let license = record
                        .get("detected")
                        .and_then(Value::as_str)
                        .or_else(|| record.get("declared").and_then(Value::as_str));
                    match license {
                        Some(license) => !allow.contains(&license),
                        None => !allow.contains(&""),
                    }
                })
                .cloned()
                .collect()
        };
        let complete = unknown.is_empty() && blocked.is_empty();
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-license-policy-result",
            "total": records.len(),
            "known": records.len() - unknown.len(),
            "unknown": unknown,
            "blocked": blocked,
            "complete": complete,
        })
    }
}

// ---------------------------------------------------------------------
// monorepo/index.mjs
// ---------------------------------------------------------------------
pub mod monorepo {
    use super::*;

    pub fn stable_id(namespace: &str, value: &Value) -> String {
        super::stable_id(namespace, value)
    }

    pub fn infer_package_manager(manifest_path: &str) -> &'static str {
        if manifest_path.ends_with("package.json") {
            "npm"
        } else if manifest_path.contains("pyproject.toml")
            || manifest_path.contains("setup.py")
            || manifest_path.contains("requirements")
        {
            "pip"
        } else if manifest_path.ends_with("Cargo.toml") {
            "cargo"
        } else if manifest_path.ends_with("go.mod") {
            "go"
        } else if manifest_path.ends_with("pom.xml") {
            "maven"
        } else if manifest_path.contains("build.gradle") {
            "gradle"
        } else if manifest_path.contains("Gemfile") {
            "bundler"
        } else {
            "unknown"
        }
    }

    pub fn component_identity(input: &Value) -> Value {
        let repo_id = input.get("repoId").cloned().unwrap_or(Value::Null);
        let manifest_path = input.get("manifestPath").cloned().unwrap_or(Value::Null);
        let package_name = input.get("packageName").cloned().unwrap_or(Value::Null);
        let id = stable_id(
            "component",
            &serde_json::json!({ "repoId": repo_id, "manifestPath": manifest_path, "packageName": package_name }),
        );
        let package_manager = manifest_path
            .as_str()
            .map(infer_package_manager)
            .unwrap_or("unknown");
        serde_json::json!({
            "id": id,
            "root": Value::Null,
            "manifestPath": manifest_path,
            "packageManager": package_manager,
            "languageIds": Value::Array(vec![]),
            "frameworkIds": Value::Array(vec![]),
            "dependencies": Value::Array(vec![]),
            "dependents": Value::Array(vec![]),
            "generatedPaths": Value::Array(vec![]),
            "vendoredPaths": Value::Array(vec![]),
        })
    }

    pub fn component_denominator(components: &[Value], exclude: &[String]) -> Value {
        let kept: Vec<&Value> = components
            .iter()
            .filter(|component| {
                let manifest_path = component.get("manifestPath").and_then(Value::as_str);
                match manifest_path {
                    Some(path) => !exclude.iter().any(|excluded| excluded == path),
                    None => true,
                }
            })
            .collect();
        let mut ids: Vec<&str> = kept
            .iter()
            .filter_map(|component| component.get("id").and_then(Value::as_str))
            .collect();
        ids.sort_unstable();
        let digest = stable_id(
            "component-denominator",
            &Value::Array(ids.iter().map(|id| Value::String((*id).into())).collect()),
        );
        serde_json::json!({
            "componentCount": kept.len(),
            "components": ids,
            "digest": digest,
        })
    }

    pub fn reconcile_components(components: &[Value], results: &[Value]) -> Value {
        let by_id: Map<String, Value> = components
            .iter()
            .filter_map(|component| {
                component
                    .get("id")
                    .and_then(Value::as_str)
                    .map(|id| (id.to_owned(), component.clone()))
            })
            .collect();
        let mut incomplete = Vec::new();
        for result in results {
            let complete = result.get("complete") == Some(&Value::Bool(true));
            if !complete {
                let component_id = result.get("componentId").cloned().unwrap_or(Value::Null);
                let manifest_path = component_id
                    .as_str()
                    .and_then(|id| by_id.get(id))
                    .and_then(|component| component.get("manifestPath"))
                    .cloned()
                    .unwrap_or(Value::Null);
                incomplete.push(serde_json::json!({
                    "componentId": component_id,
                    "manifestPath": manifest_path,
                    "status": result.get("status").cloned().unwrap_or(Value::Null),
                }));
            }
        }
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-component-reconciliation",
            "componentCount": components.len(),
            "complete": incomplete.is_empty(),
            "incomplete": incomplete,
        })
    }
}

// ---------------------------------------------------------------------
// systems/custom-grammar.mjs
// ---------------------------------------------------------------------
pub mod systems {
    use super::*;

    pub fn custom_grammar_record(input: &Value) -> Result<Value, String> {
        let source = input
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("host-config");
        if source != "host-config" {
            return Err(format!(
                "custom grammar source must be host-config; got {source}"
            ));
        }
        let abi = input.get("abi").and_then(Value::as_str).unwrap_or("tree-sitter");
        Ok(serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-custom-grammar",
            "languageId": input.get("languageId").cloned().unwrap_or(Value::Null),
            "grammarPath": input.get("grammarPath").cloned().unwrap_or(Value::Null),
            "grammarDigest": input.get("grammarDigest").cloned().unwrap_or(Value::Null),
            "source": source,
            "abi": abi,
            "qualified": false,
            "qualificationArtifact": Value::Null,
        }))
    }

    pub fn stable_grammar_id(language_id: &str, grammar_digest: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"custom-grammar\0");
        hasher.update(language_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(grammar_digest.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub fn reject_repository_grammar(repository_config: &Value) -> Result<bool, String> {
        let has_path = truthy(repository_config.get("grammarPath"));
        let has_digest = truthy(repository_config.get("grammarDigest"));
        if has_path || has_digest {
            return Err(
                "repository config may not introduce custom grammar path or digest".into(),
            );
        }
        Ok(true)
    }
}

// ---------------------------------------------------------------------
// sbom/index.mjs
// ---------------------------------------------------------------------
pub mod sbom {
    use super::*;

    pub fn syft_command(input: &Value) -> Value {
        let resolved_syft = input.get("resolvedSyft").cloned().unwrap_or(Value::Null);
        let cyclonedx_path = input.get("cycloneDxPath").and_then(Value::as_str).unwrap_or("");
        let spdx_path = input.get("spdxPath").and_then(Value::as_str).unwrap_or("");
        let repository_root = input.get("repositoryRoot").and_then(Value::as_str).unwrap_or("");
        let policy = input.get("policy").cloned().unwrap_or(Value::Null);
        let timeout_ms = policy
            .get("providerTimeoutMs")
            .and_then(Value::as_u64)
            .unwrap_or(120_000);
        let max_output_bytes = policy
            .get("maxOutputBytes")
            .and_then(Value::as_u64)
            .unwrap_or(8_388_608);
        serde_json::json!({
            "executable": resolved_syft,
            "args": [
                format!("dir:{repository_root}"),
                "-o", format!("cyclonedx-json={cyclonedx_path}"),
                "-o", format!("spdx-json={spdx_path}"),
            ],
            "cwd": repository_root,
            "timeoutMs": timeout_ms,
            "maxOutputBytes": max_output_bytes,
            "environmentKeys": ["PATH", "HOME", "USERPROFILE", "TEMP", "TMP"],
        })
    }

    pub fn sbom_receipt(input: &Value) -> Value {
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-sbom-receipt",
            "provider": "sbom.syft",
            "providerVersion": input.get("providerVersion").cloned().unwrap_or(Value::Null),
            "packageCount": input.get("packageCount").cloned().unwrap_or(Value::Null),
            "sourceScope": input.get("sourceScope").cloned().unwrap_or(Value::Null),
            "toolVersion": input.get("syftVersion").cloned().unwrap_or(Value::Null),
            "artifacts": [
                { "kind": "cyclonedx-json", "path": input.get("cycloneDxPath").cloned().unwrap_or(Value::Null), "digest": input.get("cycloneDxDigest").cloned().unwrap_or(Value::Null) },
                { "kind": "spdx-json", "path": input.get("spdxPath").cloned().unwrap_or(Value::Null), "digest": input.get("spdxDigest").cloned().unwrap_or(Value::Null) },
            ],
        })
    }
}

// ---------------------------------------------------------------------
// trust-safety/deceptive-design.mjs
// ---------------------------------------------------------------------
pub mod trust_safety {
    use super::*;

    pub fn analyze_deceptive_design(input: &Value) -> Value {
        let choices: Vec<Value> = input
            .get("choices")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut findings = Vec::new();
        let mut candidates = Vec::new();
        let coverage_gaps: Vec<Value> = if choices.is_empty() {
            vec![Value::String("choice-denominator-missing".into())]
        } else {
            vec![]
        };
        for choice in &choices {
            let id = choice.get("id").cloned().unwrap_or(Value::Null);
            let action = choice
                .get("action")
                .cloned()
                .unwrap_or_else(|| id.clone());
            let evidence = choice.get("evidence").cloned().unwrap_or_else(|| {
                Value::String(format!(
                    "choice:{}",
                    id.as_str().unwrap_or_default()
                ))
            });
            let base = serde_json::json!({
                "choiceId": id,
                "flowId": choice.get("flowId").cloned().unwrap_or(Value::Null),
                "policyContext": choice.get("policyContext").cloned().unwrap_or(Value::String("unknown".into())),
                "action": action,
                "consequence": choice.get("consequence").cloned().unwrap_or(Value::Null),
                "evidence": evidence,
            });
            let deterministic = ["preselected", "hiddenCost", "cancellationAsymmetry", "disguisedControl", "falselyLabeled", "ownerlessModeration", "policyInconsistent"]
                .iter()
                .any(|key| choice.get(*key) == Some(&Value::Bool(true)));
            if deterministic {
                let mut finding = base.as_object().cloned().unwrap_or_default();
                finding.insert("ruleId".into(), Value::String("trust-safety.deceptive-design-deterministic".into()));
                finding.insert("judgmentClass".into(), Value::String("deterministic".into()));
                findings.push(Value::Object(finding));
            }
            let interpretive = ["confirmshaming", "unsupportedUrgency", "intentConcern"]
                .iter()
                .any(|key| choice.get(*key) == Some(&Value::Bool(true)));
            if interpretive {
                let mut candidate = base.as_object().cloned().unwrap_or_default();
                candidate.insert("ruleId".into(), Value::String("trust-safety.deceptive-design-interpretive".into()));
                candidate.insert("judgmentClass".into(), Value::String("interpretive".into()));
                candidate.insert("reviewRequired".into(), Value::Bool(true));
                candidates.push(Value::Object(candidate));
            }
        }
        let status = if !findings.is_empty() || !candidates.is_empty() {
            "candidates"
        } else if !coverage_gaps.is_empty() {
            "unproven"
        } else {
            "pass"
        };
        serde_json::json!({
            "provider": "trust-safety.deceptive-design",
            "status": status,
            "findings": findings,
            "candidates": candidates,
            "coverageGaps": coverage_gaps,
            "legalConclusion": Value::Null,
        })
    }
}

// ---------------------------------------------------------------------
// generic/index.mjs :: lexicalAccounting
// ---------------------------------------------------------------------
pub mod generic {
    use super::*;
    use std::collections::BTreeSet;

    pub fn lexical_accounting(input: &Value) -> Value {
        let files: Vec<&str> = input
            .get("files")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut extensions: BTreeSet<String> = BTreeSet::new();
        for file in &files {
            let ext = file
                .rsplit('.')
                .next()
                .filter(|candidate| candidate != file)
                .unwrap_or("")
                .to_lowercase();
            extensions.insert(ext);
        }
        let parsed: BTreeSet<String> = input
            .get("parsedExtensions")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.to_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        let unsupported: Vec<String> = extensions
            .iter()
            .filter(|ext| !ext.is_empty() && !parsed.contains(*ext))
            .cloned()
            .collect();
        let coverage_gaps: Vec<Value> = unsupported
            .iter()
            .map(|ext| serde_json::json!({ "kind": "unsupported-extension", "extension": ext }))
            .collect();
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-lexical-accounting",
            "fileCount": files.len(),
            "parsedExtensions": parsed.into_iter().collect::<Vec<_>>(),
            "unsupportedExtensions": unsupported,
            "precisionTier": "lexical",
            "coverageGaps": coverage_gaps,
        })
    }
}

// ---------------------------------------------------------------------
// codeql/index.mjs
// ---------------------------------------------------------------------
pub mod codeql {
    use super::*;

    pub fn imported_sarif_receipt(input: &Value) -> Value {
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-imported-sarif",
            "provider": input.get("provider").cloned().unwrap_or(Value::Null),
            "providerVersion": input.get("providerVersion").cloned().unwrap_or(Value::Null),
            "sourceArtifact": input.get("sourceArtifact").cloned().unwrap_or(Value::Null),
            "repositoryBinding": input.get("repositoryBinding").cloned().unwrap_or(Value::Null),
            "tool": input.get("tool").cloned().unwrap_or(Value::Null),
            "capabilities": input.get("capabilities").cloned().unwrap_or(Value::Object(Map::new())),
            "complete": true,
            "coverageGaps": Value::Array(vec![]),
        })
    }

    pub fn assert_repository_binding(receipt: &Value, plan: &Value) -> Result<bool, String> {
        let plan_revision = plan
            .get("binding")
            .and_then(|binding| binding.get("repositoryRevision"))
            .and_then(Value::as_str);
        let Some(plan_revision) = plan_revision else {
            return Err("plan has no repository revision to bind against".into());
        };
        let provider = receipt.get("provider").and_then(Value::as_str).unwrap_or("");
        let receipt_revision = receipt
            .get("repositoryBinding")
            .and_then(|binding| binding.get("repositoryRevision"))
            .and_then(Value::as_str);
        let Some(receipt_revision) = receipt_revision else {
            return Err(format!("SARIF from {provider} has no repository binding"));
        };
        if receipt_revision != plan_revision {
            return Err(format!(
                "SARIF repository binding {receipt_revision} does not match plan revision {plan_revision}"
            ));
        }
        Ok(true)
    }

    pub fn sarif_source_digest(uri: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"sarif-source\0");
        hasher.update(uri.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }
}

// ---------------------------------------------------------------------
// discoverability/core.mjs :: assessDiscoverability
// ---------------------------------------------------------------------
pub mod discoverability {
    use super::*;

    pub fn assess_discoverability(input: &Value) -> Value {
        let pages: Vec<Value> = input
            .get("pages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let policy = input.get("policy").cloned().unwrap_or(Value::Object(Map::new()));
        let require_canonical = policy.get("requireCanonical") == Some(&Value::Bool(true));
        let mut findings = Vec::new();
        for page in &pages {
            let indexable = page.get("indexable") == Some(&Value::Bool(true));
            let id = page.get("id").cloned().unwrap_or(Value::Null);
            if indexable && !truthy(page.get("title")) {
                findings.push(serde_json::json!({ "ruleId": "discoverability.title-missing", "page": id }));
            }
            if indexable && !truthy(page.get("description")) {
                findings.push(serde_json::json!({ "ruleId": "discoverability.description-missing", "page": id }));
            }
            if indexable && require_canonical && !truthy(page.get("canonical")) {
                findings.push(serde_json::json!({ "ruleId": "discoverability.canonical-missing", "page": id }));
            }
        }
        let coverage_gaps: Vec<Value> = pages
            .iter()
            .filter(|page| page.get("indexable").is_none())
            .map(|page| {
                Value::String(format!(
                    "indexability-unknown:{}",
                    page.get("id").and_then(Value::as_str).unwrap_or_default()
                ))
            })
            .collect();
        let status = if findings.is_empty() { "pass" } else { "candidates" };
        serde_json::json!({
            "schemaVersion": 1,
            "provider": "discoverability.core",
            "status": status,
            "findings": findings,
            "coverageGaps": coverage_gaps,
        })
    }
}

// ---------------------------------------------------------------------
// reliability/runtime/core.mjs :: assessRuntimeReliability
// ---------------------------------------------------------------------
pub mod reliability_runtime {
    use super::*;

    pub fn assess_runtime_reliability(receipts: &[Value]) -> Value {
        let failed: Vec<&Value> = receipts
            .iter()
            .filter(|receipt| receipt.get("status").and_then(Value::as_str) != Some("pass"))
            .collect();
        let any_fail = failed
            .iter()
            .any(|receipt| receipt.get("status").and_then(Value::as_str) == Some("fail"));
        let status = if any_fail {
            "fail"
        } else if !failed.is_empty() {
            "unproven"
        } else {
            "pass"
        };
        let coverage_gaps: Vec<Value> = failed
            .iter()
            .map(|receipt| {
                receipt
                    .get("reason")
                    .cloned()
                    .unwrap_or_else(|| {
                        Value::String(format!(
                            "runtime-receipt:{}",
                            receipt.get("id").and_then(Value::as_str).unwrap_or("unknown")
                        ))
                    })
            })
            .collect();
        serde_json::json!({
            "schemaVersion": 1,
            "provider": "reliability.runtime",
            "status": status,
            "complete": failed.is_empty(),
            "receipts": receipts,
            "coverageGaps": coverage_gaps,
        })
    }
}

// ---------------------------------------------------------------------
// governance/index.mjs — needs evidence authority (validate_refs)
// ---------------------------------------------------------------------
pub mod governance {
    use super::*;

    pub fn policy_evidence(value: &Value) -> Result<Value, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "provider input must be an object".to_owned())?;
        for key in ["policy", "owner", "authority", "status", "disposition", "expiresAt"] {
            if !truthy(object.get(key)) {
                return Err(format!("policy {key} required"));
            }
        }
        let status = object.get("status").and_then(Value::as_str).unwrap_or("");
        let evidence_list = object
            .get("evidence")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if status == "verified" && evidence_list.is_empty() {
            return Err("verified policy evidence required".into());
        }
        let mut result = object.clone();
        result.insert("evidence".into(), Value::Array(evidence_list));
        result.insert("certificationClaim".into(), Value::Bool(false));
        Ok(Value::Object(result))
    }

    /// Port of `governance/index.mjs::analyze`.
    pub fn analyze(input: &Value) -> Result<Value, String> {
        let object = input
            .as_object()
            .ok_or_else(|| "provider input must be an object".to_owned())?;
        let policies: Vec<Value> = object
            .get("artifacts")
            .and_then(|value| value.get("policies"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let authority = evidence::authority(
            object.get("plan"),
            object.get("artifacts"),
            object.get("root"),
            object.get("now").and_then(Value::as_str),
        );
        let now = object.get("now").and_then(Value::as_str).unwrap_or("");
        let instant = parse_date_ms(now);
        let mut normalized = Vec::new();
        let mut gaps = Vec::new();
        for policy in &policies {
            match policy_evidence(policy).and_then(|row| {
                let expires_at = row.get("expiresAt").and_then(Value::as_str).unwrap_or("");
                let expires_ms = parse_date_ms(expires_at);
                if instant.is_none() || expires_ms.map(|e| e <= instant.unwrap()).unwrap_or(true) {
                    return Err("policy evidence expired or clock absent".into());
                }
                if row.get("status").and_then(Value::as_str) == Some("verified") {
                    let errors = evidence::validate_refs(row.get("evidence"), &authority);
                    if !errors.is_empty() {
                        return Err(errors.join(","));
                    }
                }
                Ok(row)
            }) {
                Ok(row) => normalized.push(row),
                Err(reason) => gaps.push(serde_json::json!({ "kind": "policy-evidence-invalid", "reason": reason })),
            }
        }
        if policies.is_empty() {
            gaps.push(serde_json::json!({ "kind": "policy-denominator-zero" }));
        }
        let findings: Vec<Value> = normalized
            .iter()
            .filter(|row| row.get("status").and_then(Value::as_str) != Some("verified"))
            .cloned()
            .collect();
        let status = if gaps.is_empty() { "pass" } else { "unproven" };
        Ok(serde_json::json!({
            "status": status,
            "complete": gaps.is_empty(),
            "denominator": { "kind": "governance-policies", "expected": policies.len(), "examined": normalized.len() },
            "findings": findings,
            "coverageGaps": gaps,
        }))
    }

    /// Minimal `Date.parse`-equivalent producing whole milliseconds, matching
    /// the precision the JS source compares with `<=`. Reuses the same civil
    /// calendar algorithm as `architecture::evidence`, at millisecond grain.
    fn parse_date_ms(raw: &str) -> Option<i64> {
        let normalized = raw.strip_suffix('Z').unwrap_or(raw);
        let mut parts = normalized.splitn(2, 'T');
        let date_part = parts.next()?;
        let time_part = parts.next().unwrap_or("00:00:00");
        let date_nums: Vec<i64> = date_part.split('-').filter_map(|p| p.parse().ok()).collect();
        if date_nums.len() != 3 {
            return None;
        }
        let time_and_ms: Vec<&str> = time_part.splitn(2, '.').collect();
        let time_nums: Vec<i64> = time_and_ms[0].split(':').filter_map(|p| p.parse().ok()).collect();
        if time_nums.len() != 3 {
            return None;
        }
        let ms: i64 = time_and_ms.get(1).and_then(|f| f.get(0..3.min(f.len()))).and_then(|f| f.parse().ok()).unwrap_or(0);
        let (year, month, day) = (date_nums[0], date_nums[1], date_nums[2]);
        let adjusted = year - i64::from(month <= 2);
        let era = (if adjusted >= 0 { adjusted } else { adjusted - 399 }) / 400;
        let year_of_era = adjusted - era * 400;
        let month_prime = month + if month > 2 { -3 } else { 9 };
        let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146097 + day_of_era - 719468;
        Some(days * 86_400_000 + time_nums[0] * 3_600_000 + time_nums[1] * 60_000 + time_nums[2] * 1000 + ms)
    }
}

// ---------------------------------------------------------------------
// provenance/index.mjs
// ---------------------------------------------------------------------
pub mod provenance {
    use super::*;
    use std::collections::BTreeSet;

    pub fn reconcile_sbom(input: &Value) -> Value {
        let lock_packages: Vec<String> = input
            .get("lockPackages")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default();
        let sbom_packages: BTreeSet<String> = input
            .get("sbomPackages")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default();
        let missing: Vec<String> = lock_packages
            .iter()
            .filter(|item| !sbom_packages.contains(*item))
            .cloned()
            .collect();
        let provenance = if truthy(input.get("provenance")) { "present" } else { "absent" };
        serde_json::json!({
            "complete": missing.is_empty(),
            "missing": missing,
            "provenance": provenance,
        })
    }

    fn valid_digest(value: Option<&Value>) -> bool {
        let Some(value) = value.and_then(Value::as_str) else { return false };
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }

    fn same_binding(actual: Option<&Value>, expected: Option<&Value>) -> bool {
        let Some(actual) = actual.and_then(Value::as_object) else { return false };
        let Some(expected) = expected.and_then(Value::as_object) else { return false };
        actual.get("repositoryRevision") == expected.get("repositoryRevision")
            && actual.get("digest") == expected.get("digest")
    }

    /// Port of `provenance/index.mjs::analyze`.
    pub fn analyze(input: &Value) -> Value {
        let plan = input.get("plan");
        let empty_object = Value::Object(Map::new());
        let supply_chain = input
            .get("artifacts")
            .and_then(|v| v.get("supplyChain"))
            .unwrap_or(&empty_object);
        let receipt = reconcile_sbom(supply_chain);
        let missing: Vec<&str> = receipt
            .get("missing")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut gaps: Vec<Value> = missing
            .iter()
            .map(|name| serde_json::json!({ "kind": "sbom-package-missing", "name": name }))
            .collect();
        let lock_packages = supply_chain
            .get("lockPackages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let sbom_packages = supply_chain
            .get("sbomPackages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if lock_packages.is_empty() {
            gaps.push(serde_json::json!({ "kind": "dependency-inventory-missing" }));
        }
        if !valid_digest(supply_chain.get("cycloneDxDigest")) || !valid_digest(supply_chain.get("spdxDigest")) {
            gaps.push(serde_json::json!({ "kind": "sbom-artifact-missing" }));
        }
        let provenance_field = supply_chain.get("provenance");
        let binding_ok = same_binding(
            provenance_field.and_then(|p| p.get("binding")),
            plan.and_then(|p| p.get("binding")),
        );
        let execution_complete = provenance_field
            .and_then(|p| p.get("executionReceipt"))
            .and_then(|r| r.get("complete"))
            == Some(&Value::Bool(true));
        let tool_digest_ok = valid_digest(
            provenance_field
                .and_then(|p| p.get("executionReceipt"))
                .and_then(|r| r.get("tool"))
                .and_then(|t| t.get("executableDigest")),
        );
        let subject_digest_ok = valid_digest(provenance_field.and_then(|p| p.get("subjectDigest")));
        if !binding_ok || !execution_complete || !tool_digest_ok || !subject_digest_ok {
            gaps.push(serde_json::json!({ "kind": "supply-chain-provenance-invalid" }));
        }
        let status = if gaps.is_empty() { "pass" } else { "unproven" };
        serde_json::json!({
            "status": status,
            "complete": gaps.is_empty(),
            "denominator": { "kind": "lockfile-packages", "expected": lock_packages.len(), "examined": sbom_packages.len() },
            "findings": Value::Array(vec![]),
            "coverageGaps": gaps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_integrity_facts_tag_every_operation() {
        let out = data_integrity::integrity_facts(&[serde_json::json!({"op": "write"})]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["kind"], "integrity");
        assert_eq!(out[0]["evidenceRequired"], true);
    }

    #[test]
    fn privacy_facts_marks_no_legal_conclusion() {
        let out = privacy::privacy_facts(&[serde_json::json!({"id": "r1"})]);
        assert_eq!(out[0]["kind"], "privacy");
        assert_eq!(out[0]["legalConclusion"], false);
        assert_eq!(out[0]["id"], "r1");
    }

    #[test]
    fn locale_map_flags_missing_locales() {
        let out = i18n::build_locale_map(&serde_json::json!({
            "defaultLocale": "en",
            "locales": ["en", "fr"],
            "surfaces": [{"id": "home", "locales": ["en"]}],
        }));
        assert_eq!(out["status"], "partial");
        assert_eq!(out["missing"][0]["surfaceId"], "home");
        assert_eq!(out["missing"][0]["locale"], "fr");
    }

    #[test]
    fn locale_map_passes_when_fully_covered() {
        let out = i18n::build_locale_map(&serde_json::json!({
            "locales": ["en"],
            "surfaces": [{"id": "home", "locales": ["en"]}],
        }));
        assert_eq!(out["status"], "pass");
        assert_eq!(out["missing"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn narrative_model_flags_missing_purpose() {
        let model = narrative::build_narrative_model(&[
            serde_json::json!({"id": "u1", "text": "hello"}),
        ]);
        assert_eq!(model["complete"], true);
        assert_eq!(model["coverageGaps"][0], "purpose-missing:u1");
    }

    #[test]
    fn narrative_continuity_flags_empty_unit() {
        let model = serde_json::json!({
            "units": [{"id": "u0", "text": "ok"}, {"id": "u1", "text": "   "}],
        });
        let out = narrative::assess_continuity(&model);
        assert_eq!(out["status"], "candidates");
        assert_eq!(out["findings"][0]["id"], "u1");
    }

    #[test]
    fn narrative_continuity_unproven_when_model_incomplete() {
        let model = serde_json::json!({ "units": [], "complete": false });
        let out = narrative::assess_continuity(&model);
        assert_eq!(out["status"], "unproven");
    }

    #[test]
    fn copy_facts_flags_empty_and_interpolation_and_limit() {
        let items = serde_json::json!([
            {"id": "a", "text": ""},
            {"id": "b", "text": "hi {{name}}", "surface": {"type": "button"}},
            {"id": "c", "text": "0123456789", "surface": {"type": "button"}},
        ]);
        let limits = serde_json::json!({"button": 5});
        let out = copy::copy_facts(items.as_array().unwrap(), &limits);
        assert_eq!(out["status"], "candidates");
        let rules: Vec<&str> = out["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["ruleId"].as_str().unwrap())
            .collect();
        assert!(rules.contains(&"copy.empty"));
        assert!(rules.contains(&"copy.unresolved-interpolation"));
        assert!(rules.contains(&"copy.hard-limit"));
    }

    #[test]
    fn copy_terminology_finds_alias_and_requires_authoritative_context() {
        let items = serde_json::json!([{"id": "a", "text": "click the Submit button"}]);
        let context = serde_json::json!({
            "terms": [{"canonical": "Send", "aliases": ["Submit", "Send"]}],
        });
        let out = copy::check_terminology(items.as_array().unwrap(), &context);
        assert_eq!(out["status"], "unproven");
        assert_eq!(out["coverageGaps"][0], "voice-context-missing");
        assert_eq!(out["findings"][0]["alias"], "Submit");

        let authoritative_context = serde_json::json!({
            "authoritative": true,
            "terms": [{"canonical": "Send", "aliases": ["Submit", "Send"]}],
        });
        let out2 = copy::check_terminology(items.as_array().unwrap(), &authoritative_context);
        assert_eq!(out2["status"], "candidates");
    }

    #[test]
    fn licenses_normalize_and_policy_result() {
        let record = licenses::normalize_license(&serde_json::json!({
            "name": "left-pad", "version": "1.0.0", "detected": "MIT",
        }));
        assert_eq!(record["status"], "known");
        let unknown_record = licenses::normalize_license(&serde_json::json!({"name": "x", "version": "1"}));
        assert_eq!(unknown_record["status"], "unknown");
        let policy_out = licenses::policy_result(&[record, unknown_record], &serde_json::json!({"allow": ["MIT"]}));
        assert_eq!(policy_out["total"], 2);
        assert_eq!(policy_out["known"], 1);
        assert_eq!(policy_out["complete"], false);
    }

    #[test]
    fn monorepo_infers_package_manager_and_denominator() {
        assert_eq!(monorepo::infer_package_manager("services/api/package.json"), "npm");
        assert_eq!(monorepo::infer_package_manager("engine/Cargo.toml"), "cargo");
        assert_eq!(monorepo::infer_package_manager("weird/manifest.xyz"), "unknown");

        let components = vec![
            monorepo::component_identity(&serde_json::json!({"repoId": "r", "manifestPath": "a/package.json", "packageName": "a"})),
            monorepo::component_identity(&serde_json::json!({"repoId": "r", "manifestPath": "b/Cargo.toml", "packageName": "b"})),
        ];
        let denom = monorepo::component_denominator(&components, &[]);
        assert_eq!(denom["componentCount"], 2);
    }

    #[test]
    fn systems_rejects_non_host_config_source() {
        let err = systems::custom_grammar_record(&serde_json::json!({"languageId": "x", "source": "repo"})).unwrap_err();
        assert!(err.contains("host-config"));
        let ok = systems::custom_grammar_record(&serde_json::json!({"languageId": "x"})).unwrap();
        assert_eq!(ok["source"], "host-config");
    }

    #[test]
    fn systems_rejects_repository_supplied_grammar_path() {
        let err = systems::reject_repository_grammar(&serde_json::json!({"grammarPath": "x"})).unwrap_err();
        assert!(err.contains("may not introduce"));
        assert!(systems::reject_repository_grammar(&serde_json::json!({"grammarId": "x"})).unwrap());
    }

    #[test]
    fn trust_safety_classifies_deterministic_and_interpretive() {
        let out = trust_safety::analyze_deceptive_design(&serde_json::json!({
            "choices": [
                {"id": "c1", "preselected": true},
                {"id": "c2", "confirmshaming": true},
                {"id": "c3"},
            ],
        }));
        assert_eq!(out["status"], "candidates");
        assert_eq!(out["findings"].as_array().unwrap().len(), 1);
        assert_eq!(out["candidates"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn trust_safety_reports_denominator_gap_when_empty() {
        let out = trust_safety::analyze_deceptive_design(&serde_json::json!({"choices": []}));
        assert_eq!(out["status"], "unproven");
        assert_eq!(out["coverageGaps"][0], "choice-denominator-missing");
    }

    #[test]
    fn generic_lexical_accounting_flags_unsupported_extensions() {
        let out = generic::lexical_accounting(&serde_json::json!({
            "files": ["a.rs", "b.py", "c.rs"],
            "parsedExtensions": ["rs"],
        }));
        assert_eq!(out["fileCount"], 3);
        assert_eq!(out["unsupportedExtensions"][0], "py");
    }

    #[test]
    fn codeql_binding_mismatch_is_rejected() {
        let receipt = codeql::imported_sarif_receipt(&serde_json::json!({
            "provider": "codeql", "repositoryBinding": {"repositoryRevision": "abc"},
        }));
        let plan_ok = serde_json::json!({"binding": {"repositoryRevision": "abc"}});
        assert!(codeql::assert_repository_binding(&receipt, &plan_ok).is_ok());
        let plan_bad = serde_json::json!({"binding": {"repositoryRevision": "def"}});
        assert!(codeql::assert_repository_binding(&receipt, &plan_bad).is_err());
    }

    #[test]
    fn discoverability_flags_missing_title_and_description() {
        let out = discoverability::assess_discoverability(&serde_json::json!({
            "pages": [{"id": "p1", "indexable": true}],
        }));
        assert_eq!(out["status"], "candidates");
        assert_eq!(out["findings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn reliability_runtime_fails_when_any_receipt_fails() {
        let out = reliability_runtime::assess_runtime_reliability(&[
            serde_json::json!({"id": "r1", "status": "pass"}),
            serde_json::json!({"id": "r2", "status": "fail"}),
        ]);
        assert_eq!(out["status"], "fail");
        assert_eq!(out["complete"], false);
    }

    #[test]
    fn reliability_runtime_unproven_when_only_non_pass_non_fail() {
        let out = reliability_runtime::assess_runtime_reliability(&[
            serde_json::json!({"id": "r1", "status": "skipped"}),
        ]);
        assert_eq!(out["status"], "unproven");
    }

    #[test]
    fn governance_policy_evidence_requires_all_fields() {
        let err = governance::policy_evidence(&serde_json::json!({"policy": "p"})).unwrap_err();
        assert!(err.contains("owner required"));
    }

    #[test]
    fn governance_policy_evidence_requires_evidence_when_verified() {
        let value = serde_json::json!({
            "policy": "p", "owner": "o", "authority": "a", "status": "verified",
            "disposition": "d", "expiresAt": "2099-01-01T00:00:00Z",
        });
        let err = governance::policy_evidence(&value).unwrap_err();
        assert!(err.contains("verified policy evidence required"));
    }

    #[test]
    fn governance_analyze_reports_denominator_zero_gap_when_empty() {
        let out = governance::analyze(&serde_json::json!({"artifacts": {"policies": []}})).unwrap();
        assert_eq!(out["status"], "unproven");
        assert_eq!(out["coverageGaps"][0]["kind"], "policy-denominator-zero");
    }

    #[test]
    fn governance_analyze_rejects_expired_policy() {
        let out = governance::analyze(&serde_json::json!({
            "now": "2026-01-01T00:00:00Z",
            "artifacts": {"policies": [{
                "policy": "p", "owner": "o", "authority": "a", "status": "draft",
                "disposition": "d", "expiresAt": "2020-01-01T00:00:00Z",
            }]},
        })).unwrap();
        assert_eq!(out["status"], "unproven");
        assert_eq!(out["coverageGaps"][0]["kind"], "policy-evidence-invalid");
    }

    #[test]
    fn governance_analyze_passes_unverified_policy_within_expiry() {
        let out = governance::analyze(&serde_json::json!({
            "now": "2020-01-01T00:00:00Z",
            "artifacts": {"policies": [{
                "policy": "p", "owner": "o", "authority": "a", "status": "draft",
                "disposition": "d", "expiresAt": "2099-01-01T00:00:00Z",
            }]},
        })).unwrap();
        assert_eq!(out["status"], "pass");
        assert_eq!(out["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn provenance_reconcile_sbom_reports_missing_packages() {
        let out = provenance::reconcile_sbom(&serde_json::json!({
            "lockPackages": ["a", "b"], "sbomPackages": ["a"],
        }));
        assert_eq!(out["complete"], false);
        assert_eq!(out["missing"][0], "b");
        assert_eq!(out["provenance"], "absent");
    }

    #[test]
    fn provenance_analyze_flags_all_gap_kinds_when_input_is_empty() {
        let out = provenance::analyze(&serde_json::json!({}));
        assert_eq!(out["status"], "unproven");
        let kinds: Vec<&str> = out["coverageGaps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["kind"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"dependency-inventory-missing"));
        assert!(kinds.contains(&"sbom-artifact-missing"));
        assert!(kinds.contains(&"supply-chain-provenance-invalid"));
    }

    #[test]
    fn provenance_analyze_passes_with_full_valid_chain() {
        let digest_a = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let input = serde_json::json!({
            "plan": {"binding": {"repositoryRevision": "rev1", "digest": "d1"}},
            "artifacts": {"supplyChain": {
                "lockPackages": ["pkg"],
                "sbomPackages": ["pkg"],
                "cycloneDxDigest": digest_a,
                "spdxDigest": digest_a,
                "provenance": {
                    "binding": {"repositoryRevision": "rev1", "digest": "d1"},
                    "executionReceipt": {"complete": true, "tool": {"executableDigest": digest_a}},
                    "subjectDigest": digest_a,
                },
            }},
        });
        let out = provenance::analyze(&input);
        assert_eq!(out["status"], "pass");
        assert_eq!(out["complete"], true);
    }
}
