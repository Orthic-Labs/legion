//! Port of `skills/seo/scripts/provider_registry.py`.
//!
//! Fully ported: discovers and selects SEO evidence providers from the
//! governed registry JSON by capability, availability, first-party/local
//! preference, and paid-provider authority constraints. Never reads or
//! prints secret values — only whether an env var is set.
//!
//! The Python CLI loads the registry from a fixed path
//! (`skills/seo/config/provider-registry.json`) relative to the script;
//! here `load_registry` takes the JSON text directly so callers control the
//! source (file read, embedded asset, etc).

use std::collections::HashMap;
use std::env;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct ProviderDef {
    pub class: Option<String>,
    pub paid: Option<bool>,
    pub priority: Option<i64>,
    pub capabilities: Option<Vec<String>>,
    pub availability: Option<String>,
    pub env: Option<Vec<String>>,
    pub tool_hint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Registry {
    pub providers: HashMap<String, ProviderDef>,
    #[serde(default)]
    pub selection_rules: Vec<Value>,
}

/// Mirrors `availability()`: 'available' | 'manual' | 'unknown' | 'partial' | 'unavailable'.
pub fn availability(provider: &ProviderDef, host_tools: &std::collections::HashSet<String>) -> String {
    let kind = provider.availability.as_deref().unwrap_or("");
    let envs = provider.env.clone().unwrap_or_default();
    match kind {
        "builtin" => return "available".to_string(),
        "manual" => return "manual".to_string(),
        "host_tool" => {
            return match &provider.tool_hint {
                Some(hint) if host_tools.contains(hint) => "available".to_string(),
                _ => "unknown".to_string(),
            };
        }
        _ => {}
    }
    let vals: Vec<bool> = envs.iter().map(|name| env::var(name).is_ok()).collect();
    if kind == "env_all" {
        return if !vals.is_empty() && vals.iter().all(|v| *v) {
            "available".to_string()
        } else if vals.iter().any(|v| *v) {
            "partial".to_string()
        } else {
            "unavailable".to_string()
        };
    }
    if kind == "env_any" {
        return if vals.iter().any(|v| *v) {
            "available".to_string()
        } else {
            "unavailable".to_string()
        };
    }
    "unknown".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderSummary {
    pub class: Option<String>,
    pub paid: Option<bool>,
    pub priority: Option<i64>,
    pub capabilities: Vec<String>,
    pub availability: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Discovery {
    pub providers: HashMap<String, ProviderSummary>,
    pub selection_rules: Vec<Value>,
}

pub fn discover(registry: &Registry, host_tools: &std::collections::HashSet<String>) -> Discovery {
    let mut out = HashMap::new();
    for (name, provider) in &registry.providers {
        out.insert(
            name.clone(),
            ProviderSummary {
                class: provider.class.clone(),
                paid: provider.paid,
                priority: provider.priority,
                capabilities: provider.capabilities.clone().unwrap_or_default(),
                availability: availability(provider, host_tools),
            },
        );
    }
    Discovery {
        providers: out,
        selection_rules: registry.selection_rules.clone(),
    }
}

fn class_rank(class: Option<&str>) -> i64 {
    match class {
        Some("first_party") | Some("first_party_manual_export") => 5,
        Some("first_party_write") | Some("local") => 4,
        Some("host_tool") => 3,
        Some("paid_provider") | Some("paid_host_tool") => 2,
        _ => 1,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ChooseResult {
    Unavailable {
        status: &'static str,
        capability: String,
        reason: &'static str,
    },
    Selected {
        status: &'static str,
        capability: String,
        provider: String,
        class: Option<String>,
        availability: String,
        paid: Option<bool>,
        priority: i64,
        alternatives: Vec<String>,
    },
}

impl ChooseResult {
    pub fn is_selected(&self) -> bool {
        matches!(self, ChooseResult::Selected { .. })
    }
}

pub fn choose(
    registry: &Registry,
    capability: &str,
    host_tools: &std::collections::HashSet<String>,
    allow_paid: bool,
    allow_manual: bool,
) -> ChooseResult {
    // (class_rank, priority, name) descending, mirrors Python's tuple sort + reverse=True.
    let mut candidates: Vec<(i64, i64, String, &ProviderDef, String)> = Vec::new();
    for (name, provider) in &registry.providers {
        let caps = provider.capabilities.clone().unwrap_or_default();
        if !caps.iter().any(|c| c == capability) {
            continue;
        }
        let state = availability(provider, host_tools);
        if state == "manual" && !allow_manual {
            continue;
        }
        if state != "available" && state != "manual" {
            continue;
        }
        if provider.paid == Some(true) && !allow_paid {
            continue;
        }
        candidates.push((
            class_rank(provider.class.as_deref()),
            provider.priority.unwrap_or(0),
            name.clone(),
            provider,
            state,
        ));
    }
    // Python sorts the tuple (class_rank, priority, name, provider_dict, state) with
    // reverse=True; dicts aren't orderable but ties on (class_rank, priority, name) never
    // reach the dict since name is unique, so sorting on the first three fields is
    // equivalent and doesn't require Ord on ProviderDef.
    candidates.sort_by(|a, b| (b.0, b.1, &b.2).cmp(&(a.0, a.1, &a.2)));

    match candidates.first() {
        None => ChooseResult::Unavailable {
            status: "unavailable",
            capability: capability.to_string(),
            reason: "no eligible provider is currently available under the paid/manual policy",
        },
        Some((rank, priority, name, provider, state)) => {
            let _ = rank;
            let alternatives = candidates[1..].iter().map(|c| c.2.clone()).collect();
            ChooseResult::Selected {
                status: "selected",
                capability: capability.to_string(),
                provider: name.clone(),
                class: provider.class.clone(),
                availability: state.clone(),
                paid: provider.paid,
                priority: *priority,
                alternatives,
            }
        }
    }
}

pub fn load_registry(json_text: &str) -> Result<Registry, serde_json::Error> {
    serde_json::from_str(json_text)
}

/// CLI entry point mirroring `provider_registry.py`'s `main()`: `discover [--host-tool T]...`
/// or `choose <capability> [--host-tool T]... [--allow-paid] [--no-manual]`. `registry_json`
/// substitutes for the Python script's fixed-path `REGISTRY.read_text()` (the caller reads
/// `skills/seo/config/provider-registry.json` relative to the skill root and passes its text
/// in, since a Rust binary has no equivalent "next to this script" path). Prints the pretty
/// JSON result and returns 0 for `discover`, or for `choose`: 0 if selected, 2 otherwise
/// (matching `0 if args.command == 'discover' or result.get('status') == 'selected' else 2`).
pub fn run(argv: &[String], registry_json: &str) -> i32 {
    if argv.is_empty() {
        eprintln!("error: a command (discover|choose) is required");
        return 2;
    }
    let command = argv[0].as_str();
    let rest = &argv[1..];

    let mut host_tools: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut allow_paid = false;
    let mut no_manual = false;
    let mut capability: Option<&str> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--host-tool" => {
                i += 1;
                if let Some(v) = rest.get(i) {
                    host_tools.insert(v.clone());
                }
            }
            "--allow-paid" => allow_paid = true,
            "--no-manual" => no_manual = true,
            other if command == "choose" && capability.is_none() => capability = Some(other),
            _ => {}
        }
        i += 1;
    }

    let registry = match load_registry(registry_json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    match command {
        "discover" => {
            let result = discover(&registry, &host_tools);
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
            0
        }
        "choose" => {
            let cap = match capability {
                Some(c) => c,
                None => {
                    eprintln!("error: capability is required");
                    return 2;
                }
            };
            let result = choose(&registry, cap, &host_tools, allow_paid, !no_manual);
            let selected = result.is_selected();
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
            if selected {
                0
            } else {
                2
            }
        }
        other => {
            eprintln!("error: unknown command: {other}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Each test below builds a registry with env-var names unique to that test
    // (rather than sharing one constant registry/env-var pair), because
    // `std::env::set_var`/`remove_var` are process-global and `cargo test` runs
    // tests in parallel threads by default: sharing names would race.
    fn registry_json(gsc_env: &str, paid_env: &str) -> String {
        format!(
            r#"{{
      "providers": {{
        "gsc": {{"class": "first_party", "paid": false, "priority": 10, "capabilities": ["rank", "queries"], "availability": "env_all", "env": ["{gsc_env}"]}},
        "manual_export": {{"class": "first_party_manual_export", "paid": false, "priority": 5, "capabilities": ["rank"], "availability": "manual"}},
        "paid_rank_tool": {{"class": "paid_provider", "paid": true, "priority": 20, "capabilities": ["rank"], "availability": "env_any", "env": ["{paid_env}"]}},
        "host_tool_provider": {{"class": "host_tool", "paid": false, "priority": 1, "capabilities": ["screenshot"], "availability": "host_tool", "tool_hint": "browser"}},
        "builtin_provider": {{"class": "local", "paid": false, "priority": 1, "capabilities": ["parse"], "availability": "builtin"}}
      }},
      "selection_rules": ["prefer first-party"]
    }}"#
        )
    }

    #[test]
    fn availability_env_all_unavailable_when_unset() {
        let reg = load_registry(&registry_json("PR_T1_GSC", "PR_T1_PAID")).unwrap();
        let p = &reg.providers["gsc"];
        std::env::remove_var("PR_T1_GSC");
        assert_eq!(availability(p, &HashSet::new()), "unavailable");
    }

    #[test]
    fn availability_env_all_available_when_set() {
        let reg = load_registry(&registry_json("PR_T2_GSC", "PR_T2_PAID")).unwrap();
        let p = &reg.providers["gsc"];
        std::env::set_var("PR_T2_GSC", "1");
        assert_eq!(availability(p, &HashSet::new()), "available");
        std::env::remove_var("PR_T2_GSC");
    }

    #[test]
    fn availability_builtin_always_available() {
        let reg = load_registry(&registry_json("PR_T3_GSC", "PR_T3_PAID")).unwrap();
        let p = &reg.providers["builtin_provider"];
        assert_eq!(availability(p, &HashSet::new()), "available");
    }

    #[test]
    fn availability_host_tool_needs_hint_in_set() {
        let reg = load_registry(&registry_json("PR_T4_GSC", "PR_T4_PAID")).unwrap();
        let p = &reg.providers["host_tool_provider"];
        assert_eq!(availability(p, &HashSet::new()), "unknown");
        let mut tools = HashSet::new();
        tools.insert("browser".to_string());
        assert_eq!(availability(p, &tools), "available");
    }

    #[test]
    fn choose_prefers_first_party_over_paid_even_if_lower_priority() {
        std::env::set_var("PR_T5_GSC", "1");
        std::env::set_var("PR_T5_PAID", "1");
        let reg = load_registry(&registry_json("PR_T5_GSC", "PR_T5_PAID")).unwrap();
        let result = choose(&reg, "rank", &HashSet::new(), true, true);
        match result {
            ChooseResult::Selected { provider, .. } => assert_eq!(provider, "gsc"),
            _ => panic!("expected selection"),
        }
        std::env::remove_var("PR_T5_GSC");
        std::env::remove_var("PR_T5_PAID");
    }

    #[test]
    fn choose_excludes_paid_when_not_allowed() {
        std::env::remove_var("PR_T6_GSC");
        std::env::set_var("PR_T6_PAID", "1");
        let reg = load_registry(&registry_json("PR_T6_GSC", "PR_T6_PAID")).unwrap();
        let result = choose(&reg, "rank", &HashSet::new(), false, true);
        // gsc unavailable (no token), paid disallowed -> falls back to manual_export
        match result {
            ChooseResult::Selected { provider, .. } => assert_eq!(provider, "manual_export"),
            _ => panic!("expected manual_export selection"),
        }
        std::env::remove_var("PR_T6_PAID");
    }

    #[test]
    fn choose_excludes_manual_when_disallowed() {
        let reg = load_registry(&registry_json("PR_T7_GSC", "PR_T7_PAID")).unwrap();
        let result = choose(&reg, "rank", &HashSet::new(), false, false);
        assert!(!result.is_selected());
    }

    #[test]
    fn choose_unavailable_when_no_provider_has_capability() {
        let reg = load_registry(&registry_json("PR_T8_GSC", "PR_T8_PAID")).unwrap();
        let result = choose(&reg, "nonexistent-capability", &HashSet::new(), true, true);
        assert!(!result.is_selected());
    }

    #[test]
    fn discover_lists_every_provider() {
        let reg = load_registry(&registry_json("PR_T9_GSC", "PR_T9_PAID")).unwrap();
        let d = discover(&reg, &HashSet::new());
        assert_eq!(d.providers.len(), 5);
        assert_eq!(d.selection_rules.len(), 1);
    }

    #[test]
    fn run_discover_returns_0() {
        let json = registry_json("PR_RUN_GSC", "PR_RUN_PAID");
        assert_eq!(run(&["discover".to_string()], &json), 0);
    }

    #[test]
    fn run_choose_manual_export_selected_returns_0() {
        let json = registry_json("PR_RUN2_GSC", "PR_RUN2_PAID");
        assert_eq!(run(&["choose".to_string(), "rank".to_string()], &json), 0);
    }

    #[test]
    fn run_choose_unknown_capability_returns_2() {
        let json = registry_json("PR_RUN3_GSC", "PR_RUN3_PAID");
        assert_eq!(run(&["choose".to_string(), "nope".to_string()], &json), 2);
    }

    #[test]
    fn run_missing_command_returns_2() {
        assert_eq!(run(&[], "{\"providers\":{}}"), 2);
    }
}
