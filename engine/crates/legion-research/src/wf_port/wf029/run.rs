//! Partial port of `src/lib/research-core/run.py`'s pure decision logic:
//! provider resolution, effect-grant checking, and scale-budget selection.
//!
//! `run.py` is primarily a stateful CLI orchestrator: `init_run`, `grant`,
//! `acquire`, `record_evidence`, `record_claim`, `render_draft`,
//! `issue_patch_receipt`, `apply_draft_patch`, and `verify`/`finalize` each
//! read and write a run directory (`manifest.json`, `route.json`,
//! `evidence.jsonl`, `claims.jsonl`, `draft.md`, and half a dozen
//! `*-check.json` files) through `manifest.py`, `ledger.py`, `citecheck.py`,
//! `contradictions.py`, `gap_critic.py`, `domain_verify.py`, `retraction.py`,
//! `patcher.py`, `draft_integrity.py`, `effect_audit.py`, `meter.py`,
//! `patch_guard.py`, and the `providers/` package. None of those modules
//! has a canonical port under `legion-research` yet (checked via `git grep`
//! at port time, mirroring the check `wf023::control` and `wf024`/`wf025`/
//! `wf026` record in their own module docs); porting the full orchestrator
//! faithfully needs all of them wired first, and this chunk owns only
//! `wf_port/wf029/**`. See the packet report (`scratchpad/loss/wf/wf029.md`)
//! for the itemized remainder and the dependency order to unblock it.
//!
//! What *is* ported here, faithfully and self-contained, because it is
//! pure decision logic with no I/O: `_default_search_provider`,
//! `_resolve_acquire_provider`, `_check_effects`'s missing-effect check,
//! and the `init_run` scale-to-budget mapping (the `dossier` validation
//! branch and the fixed `focused`/`broad` budgets).

use serde_json::{json, Value};

fn field_str<'a>(route: &'a Value, key: &str) -> &'a str {
    route.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `run._default_search_provider`.
pub fn default_search_provider(route: &Value) -> String {
    let provider = field_str(route, "provider");
    if provider == "domain-default" {
        let domain = field_str(route, "domain");
        if matches!(domain, "medical" | "scientific") {
            return "scholarly".to_string();
        }
        if domain == "legal" {
            return "legal-authority".to_string();
        }
        return "browser".to_string();
    }
    provider.to_string()
}

/// `run._resolve_acquire_provider`. `requested` mirrors `str | None`.
pub fn resolve_acquire_provider(route: &Value, requested: Option<&str>) -> Result<String, String> {
    let route_provider = field_str(route, "provider").to_string();
    let mut selected = requested.map(str::to_string).unwrap_or_else(|| route_provider.clone());
    let default = default_search_provider(route);
    let mut allowed: Vec<String> = vec![route_provider.clone(), default.clone()];
    if route_provider == "domain-default" {
        allowed.push("domain-default".to_string());
    }
    if selected == "domain-default" {
        selected = default;
    }
    if !allowed.contains(&selected) {
        return Err(format!(
            "provider {selected:?} is not authorized by frozen route provider {route_provider:?}"
        ));
    }
    if selected == "notebooklm" {
        return Err(
            "NotebookLM does not expose search/open/find; answers remain leads until \
             their underlying sources are opened through an authorized provider"
                .to_string(),
        );
    }
    Ok(selected)
}

/// `run._check_effects`: raises (here, errs) listing every effect in
/// `effects` that the route's `allowed_effects` does not grant, preserving
/// the requested order (matches the Python list comprehension order, not
/// `allowed_effects`' order).
pub fn check_effects(route: &Value, effects: &[&str]) -> Result<(), String> {
    let allowed: Vec<&str> = route
        .get("allowed_effects")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let missing: Vec<&str> = effects.iter().copied().filter(|e| !allowed.contains(e)).collect();
    if !missing.is_empty() {
        return Err(format!("frozen route does not grant effects: {missing:?}"));
    }
    Ok(())
}

/// `run.init_run`'s `scale_budgets` mapping plus the `dossier` validation
/// branch. `context_budget` mirrors `context.get('budget')`: `None`/absent
/// keys behave like Python's falsy `dict.get`.
pub fn scale_budget(scale: &str, context_budget: Option<&Value>) -> Result<Value, String> {
    match scale {
        "focused" => Ok(json!({"external_requests": 12, "workers": 1})),
        "broad" => Ok(json!({"external_requests": 30, "workers": 4})),
        "dossier" => {
            let budget = context_budget.cloned().unwrap_or_else(|| json!({}));
            let external_requests = budget.get("external_requests");
            let workers = budget.get("workers");
            let requests_missing = matches!(external_requests, None | Some(Value::Null))
                || matches!(external_requests, Some(Value::Number(n)) if n.as_i64() == Some(0));
            let workers_missing = matches!(workers, None | Some(Value::Null));
            if requests_missing || workers_missing {
                return Err(
                    "dossier routes require context.budget.external_requests and context.budget.workers"
                        .to_string(),
                );
            }
            Ok(budget)
        }
        other => Err(format!("unknown scale: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(provider: &str, domain: &str) -> Value {
        json!({"provider": provider, "domain": domain, "allowed_effects": ["search", "extract"]})
    }

    #[test]
    fn default_search_provider_maps_domain_default_by_domain() {
        assert_eq!(default_search_provider(&route("domain-default", "medical")), "scholarly");
        assert_eq!(default_search_provider(&route("domain-default", "scientific")), "scholarly");
        assert_eq!(default_search_provider(&route("domain-default", "legal")), "legal-authority");
        assert_eq!(default_search_provider(&route("domain-default", "general")), "browser");
        assert_eq!(default_search_provider(&route("browser", "general")), "browser");
    }

    #[test]
    fn resolve_acquire_provider_rejects_unauthorized_and_notebooklm() {
        let r = route("browser", "general");
        assert_eq!(resolve_acquire_provider(&r, None).unwrap(), "browser");
        assert!(resolve_acquire_provider(&r, Some("local-corpus")).is_err());

        let notebooklm_route = route("notebooklm", "general");
        let err = resolve_acquire_provider(&notebooklm_route, None).unwrap_err();
        assert!(err.contains("NotebookLM does not expose"));
    }

    #[test]
    fn resolve_acquire_provider_domain_default_resolves_to_concrete_provider() {
        let r = route("domain-default", "legal");
        assert_eq!(resolve_acquire_provider(&r, None).unwrap(), "legal-authority");
        assert_eq!(resolve_acquire_provider(&r, Some("domain-default")).unwrap(), "legal-authority");
    }

    #[test]
    fn check_effects_lists_missing_in_requested_order() {
        let r = route("browser", "general");
        let err = check_effects(&r, &["fetch", "search", "citecheck"]).unwrap_err();
        assert!(err.contains(r#"["fetch", "citecheck"]"#), "{err}");
        assert!(check_effects(&r, &["search", "extract"]).is_ok());
    }

    #[test]
    fn scale_budget_dossier_requires_explicit_budget() {
        assert_eq!(scale_budget("focused", None).unwrap(), json!({"external_requests": 12, "workers": 1}));
        assert_eq!(scale_budget("broad", None).unwrap(), json!({"external_requests": 30, "workers": 4}));
        assert!(scale_budget("dossier", None).is_err());
        let budget = json!({"external_requests": 50, "workers": 2});
        assert_eq!(scale_budget("dossier", Some(&budget)).unwrap(), budget);
        let zero_requests = json!({"external_requests": 0, "workers": 2});
        assert!(scale_budget("dossier", Some(&zero_requests)).is_err());
    }
}
