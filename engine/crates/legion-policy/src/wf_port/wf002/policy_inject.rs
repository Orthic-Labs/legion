//! Rust port of `src/lib/cognitive/arcane/host/policy-inject.mjs`.
//!
//! Adaptation note: the JS source resolves `BRIEF_FALLBACK`, `MINIMIZE_POLICY`
//! and `CCX_DIRECTIVE` relative to its own file location (`import.meta.url`),
//! i.e. relative to the *arcane package*, not the caller's workspace. This
//! Rust port takes those as explicit paths (`PolicyPaths`) instead of
//! hardcoding a path relative to this crate — this crate lives in
//! `engine/crates/legion-policy`, not next to the legacy `policy/*.md`
//! files, so a baked-in relative path would silently resolve to nothing.
//! Behaviour (what gets read, in what order, and how it's assembled) is
//! otherwise identical. `workspace` still means the caller's project root —
//! `policy.toml` and `docs/GOTCHAS.md` are read relative to it, exactly as
//! in the JS source.

use regex::Regex;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const POLICY_TOML_REL: &str = "tools/lib/policy.toml";
const GOTCHAS_REL: &str = "docs/GOTCHAS.md";
const GOTCHA_LIMIT: usize = 2;

/// Paths to the three static policy documents. In the JS source these are
/// derived from `import.meta.url`; here the caller supplies them (see module
/// doc comment).
#[derive(Clone, Debug)]
pub struct PolicyPaths {
    pub brief_fallback: PathBuf,
    pub minimize_policy: PathBuf,
    pub ccx_directive: PathBuf,
}

/// Environment inputs the JS source reads via `process.env`. Passed
/// explicitly rather than through global env, matching this crate's other
/// wf002 ports and keeping the function safe to call from parallel tests.
#[derive(Clone, Debug, Default)]
pub struct PolicyEnv {
    pub brief_mode_off: bool,
    pub ccx_gateway_mode_off: bool,
    pub anthropic_base_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PolicyInjectionInput<'a> {
    pub workspace: &'a Path,
    pub prompt: Option<&'a str>,
    pub gotchas_only: bool,
    /// Pre-rendered `ARCANE_ROUTE:<json>` context, if the caller already has
    /// a route envelope (mirrors `routeEnvelope?.kind === 'arcane-route-envelope'`
    /// gating in the JS source, done by the caller before invoking this).
    pub route_context: Option<&'a str>,
}

impl<'a> Default for PolicyInjectionInput<'a> {
    /// `workspace` defaults to an empty path — every call site below always
    /// overrides it via struct-update syntax
    /// (`PolicyInjectionInput { workspace: &workspace, ..Default::default() }`),
    /// but `&Path` itself has no `Default` impl, so this manual impl exists
    /// purely to make that struct-update pattern type-check.
    fn default() -> Self {
        Self {
            workspace: Path::new(""),
            prompt: None,
            gotchas_only: false,
            route_context: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyInjection {
    pub additional_context: String,
    pub system_message: Option<String>,
}

fn read_file_or_none(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

/// `policy.toml` WINS when readable (I-4); `brief-policy.md` is the
/// fallback. `BRIEF_MODE_OFF=1` is the operator kill switch.
fn brief_content(workspace: &Path, paths: &PolicyPaths, env: &PolicyEnv) -> Option<String> {
    if env.brief_mode_off {
        return None;
    }
    static TOML_BRIEF_RE: OnceLock<Regex> = OnceLock::new();
    // JS: /\[brief\][\s\S]*?\bcontent\s*=\s*"""\n?([\s\S]*?)"""/ — three
    // closing quotes close the capture group, and TOML's own triple-quote
    // terminator follows right after.
    let re = TOML_BRIEF_RE
        .get_or_init(|| Regex::new(r#"(?s)\[brief\].*?\bcontent\s*=\s*"""\n?(.*?)""""#).unwrap());
    let toml = read_file_or_none(&workspace.join(POLICY_TOML_REL));
    if let Some(toml) = &toml {
        if let Some(captures) = re.captures(toml) {
            let matched = captures.get(1).map(|m| m.as_str().trim()).unwrap_or("");
            if !matched.is_empty() {
                return Some(matched.to_string());
            }
        }
    }
    read_file_or_none(&paths.brief_fallback).map(|s| s.trim().to_string())
}

/// `CCX_GATEWAY_MODE_OFF=1` is the operator kill switch.
fn ccx_directive(paths: &PolicyPaths, env: &PolicyEnv) -> Option<String> {
    if env.ccx_gateway_mode_off {
        return None;
    }
    let base = env.anthropic_base_url.as_deref().unwrap_or("");
    if !base.contains("127.0.0.1:8801") && !base.contains("localhost:8801") {
        return None;
    }
    read_file_or_none(&paths.ccx_directive).map(|s| s.trim().to_string())
}

fn words(value: &str) -> BTreeSet<String> {
    static WORD_RE: OnceLock<Regex> = OnceLock::new();
    let re = WORD_RE.get_or_init(|| Regex::new(r"[a-z0-9][a-z0-9_-]{2,}").unwrap());
    re.find_iter(&value.to_lowercase())
        .map(|m| m.as_str().to_string())
        .collect()
}

fn gotcha_reminder(workspace: &Path, prompt: Option<&str>) -> Option<String> {
    let prompt = prompt?;
    let prompt_words = words(prompt);
    if prompt_words.is_empty() {
        return None;
    }
    let markdown = read_file_or_none(&workspace.join(GOTCHAS_REL))?;

    static KEYS_RE: OnceLock<Regex> = OnceLock::new();
    let keys_re = KEYS_RE.get_or_init(|| Regex::new(r"(?i)^\*\*Keys:\*\*").unwrap());
    static FIX_RE: OnceLock<Regex> = OnceLock::new();
    let fix_re = FIX_RE.get_or_init(|| Regex::new(r"^\*\*Fix:\*\*").unwrap());
    static KEYS_STRIP_RE: OnceLock<Regex> = OnceLock::new();
    let keys_strip_re = KEYS_STRIP_RE.get_or_init(|| Regex::new(r"(?i)^\*\*Keys:\*\*\s*").unwrap());
    static FIX_STRIP_RE: OnceLock<Regex> = OnceLock::new();
    let fix_strip_re = FIX_STRIP_RE.get_or_init(|| Regex::new(r"^\*\*Fix:\*\*\s*").unwrap());

    let mut matches = Vec::new();
    // `markdown.split(/^### /m).slice(1)` — split on lines starting with
    // "### " (including a possible leading one at index 0), keep every
    // section after that marker.
    let mut sections: Vec<&str> = Vec::new();
    let mut parts = markdown.split("\n### ");
    let first = parts.next().unwrap_or("");
    if let Some(stripped) = first.strip_prefix("### ") {
        sections.push(stripped);
    }
    for part in parts {
        sections.push(part);
    }

    for section in sections {
        // JS: `section.split(/\r?\n/)`.
        let raw_lines: Vec<&str> = section.split("\r\n").flat_map(|l| l.split('\n')).collect();
        let heading = raw_lines.first().copied().unwrap_or("");
        let body_lines = &raw_lines[raw_lines.len().min(1)..];
        let Some(keys_line) = body_lines.iter().find(|l| keys_re.is_match(l)) else {
            continue;
        };
        let keys_value = keys_strip_re.replace(keys_line, "");
        let keys: Vec<String> = keys_value
            .split(',')
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect();
        let any_key_fully_present = keys.iter().any(|key| {
            let key_words = words(key);
            !key_words.is_empty() && key_words.iter().all(|w| prompt_words.contains(w))
        });
        if !any_key_fully_present {
            continue;
        }
        let fix_line = body_lines.iter().find(|l| fix_re.is_match(l));
        let fix_suffix = fix_line
            .map(|line| format!(" — {}", fix_strip_re.replace(line, "")))
            .unwrap_or_default();
        matches.push(format!("- {}{}", heading.trim(), fix_suffix));
        if matches.len() == GOTCHA_LIMIT {
            break;
        }
    }

    if matches.is_empty() {
        return None;
    }
    Some(format!(
        "Relevant workspace gotchas — apply before acting:\n{}",
        matches.join("\n")
    ))
}

/// Port of `buildPolicyInjection`.
pub fn build_policy_injection(
    input: &PolicyInjectionInput,
    paths: &PolicyPaths,
    env: &PolicyEnv,
) -> Option<PolicyInjection> {
    let minimize = read_file_or_none(&paths.minimize_policy).map(|s| s.trim().to_string());
    let gotcha = gotcha_reminder(input.workspace, input.prompt);
    let route = input.route_context.map(|s| s.to_string());

    let parts: Vec<String> = if input.gotchas_only {
        [route, gotcha].into_iter().flatten().collect()
    } else {
        [
            route,
            brief_content(input.workspace, paths, env),
            minimize.clone(),
            ccx_directive(paths, env),
            gotcha,
        ]
        .into_iter()
        .flatten()
        .collect()
    };

    if parts.is_empty() {
        return None;
    }
    let additional_context = parts.join("\n\n---\n\n");
    let system_message = if !input.gotchas_only && minimize.is_some() {
        Some("MINIMIZE:ON".to_string())
    } else {
        None
    };
    Some(PolicyInjection {
        additional_context,
        system_message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "legion-policy-inject-test-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn policy_source_paths() -> PolicyPaths {
        // CARGO_MANIFEST_DIR = .../engine/crates/legion-policy; three levels
        // up reaches the repo root.
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("src/lib/cognitive/arcane/policy");
        PolicyPaths {
            brief_fallback: base.join("brief-policy.md"),
            minimize_policy: base.join("minimize-policy.md"),
            ccx_directive: base.join("ccx-gateway-directive.md"),
        }
    }

    #[test]
    fn brief_and_minimize_are_injected_with_no_policy_toml() {
        let workspace = tmp_dir("no-toml");
        let paths = policy_source_paths();
        let injection = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                ..Default::default()
            },
            &paths,
            &PolicyEnv::default(),
        )
        .expect("some injection");
        assert!(injection.additional_context.contains("Brief is default"));
        assert!(injection.additional_context.contains("MINIMIZE"));
        assert_eq!(injection.system_message.as_deref(), Some("MINIMIZE:ON"));
        assert_eq!(injection.additional_context.matches("# MINIMIZE").count(), 1);
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn policy_toml_brief_wins_over_fallback() {
        let workspace = tmp_dir("toml-wins");
        fs::create_dir_all(workspace.join("tools/lib")).unwrap();
        fs::write(
            workspace.join("tools/lib/policy.toml"),
            "[brief]\ncontent = \"\"\"\nCUSTOM BRIEF TEXT FROM TOML\n\"\"\"\n",
        )
        .unwrap();
        let paths = policy_source_paths();
        let injection = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                ..Default::default()
            },
            &paths,
            &PolicyEnv::default(),
        )
        .unwrap();
        assert!(injection.additional_context.contains("CUSTOM BRIEF TEXT FROM TOML"));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn policy_toml_missing_content_key_falls_back() {
        let workspace = tmp_dir("toml-no-key");
        fs::create_dir_all(workspace.join("tools/lib")).unwrap();
        fs::write(workspace.join("tools/lib/policy.toml"), "[other]\nkey = \"value\"\n").unwrap();
        let paths = policy_source_paths();
        let injection = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                ..Default::default()
            },
            &paths,
            &PolicyEnv::default(),
        )
        .unwrap();
        // brief-policy.md fallback text starts with "Brief is default" in the
        // real repo file; assert the toml's non-content section never leaks
        // in. (Not a "CUSTOM" substring check: minimize-policy.md's real
        // content legitimately contains "MIN_CUSTOM".)
        assert!(injection.additional_context.starts_with("Brief is default"));
        assert!(!injection.additional_context.contains("[other]"));
        assert!(!injection.additional_context.contains("key = \"value\""));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn ccx_directive_present_only_on_local_gateway() {
        let workspace = tmp_dir("ccx");
        let paths = policy_source_paths();

        let none = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                ..Default::default()
            },
            &paths,
            &PolicyEnv::default(),
        )
        .unwrap();
        assert!(!none.additional_context.contains("ccx-mode"));

        let elsewhere = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                ..Default::default()
            },
            &paths,
            &PolicyEnv {
                anthropic_base_url: Some("https://api.anthropic.com".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!elsewhere.additional_context.contains("ccx-mode"));

        let gateway = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                ..Default::default()
            },
            &paths,
            &PolicyEnv {
                anthropic_base_url: Some("http://127.0.0.1:8801".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(gateway.additional_context.contains("ccx-mode"));

        let gateway_localhost = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                ..Default::default()
            },
            &paths,
            &PolicyEnv {
                anthropic_base_url: Some("http://localhost:8801/v1".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(gateway_localhost.additional_context.contains("ccx-mode"));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn brief_mode_off_silences_brief_but_not_minimize() {
        let workspace = tmp_dir("brief-off");
        let paths = policy_source_paths();
        let out = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                ..Default::default()
            },
            &paths,
            &PolicyEnv {
                brief_mode_off: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!out.additional_context.contains("Brief is default"));
        assert_eq!(out.system_message.as_deref(), Some("MINIMIZE:ON"));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn ccx_gateway_mode_off_silences_directive_even_on_gateway() {
        let workspace = tmp_dir("ccx-off");
        let paths = policy_source_paths();
        let out = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                ..Default::default()
            },
            &paths,
            &PolicyEnv {
                ccx_gateway_mode_off: true,
                anthropic_base_url: Some("http://127.0.0.1:8801".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!out.additional_context.contains("ccx-mode"));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn prompt_keys_inject_only_matching_capped_gotchas() {
        let workspace = tmp_dir("gotchas-match");
        fs::create_dir_all(workspace.join("docs")).unwrap();
        fs::write(
            workspace.join("docs/GOTCHAS.md"),
            [
                "# Gotchas",
                "### Archive safely",
                "**Keys:** task archive, worktree",
                "**Fix:** prove commit reachability first.",
                "### Commit serially",
                "**Keys:** parallel commit, isolated index",
                "**Fix:** use one integration owner.",
                "### Unrelated",
                "**Keys:** signing certificate",
                "**Fix:** use release tooling.",
            ]
            .join("\n"),
        )
        .unwrap();
        let paths = policy_source_paths();
        let out = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                prompt: Some("Archive this task worktree after its commit is reachable."),
                ..Default::default()
            },
            &paths,
            &PolicyEnv::default(),
        )
        .unwrap();
        assert!(out.additional_context.contains("Archive safely"));
        assert!(out.additional_context.contains("prove commit reachability first"));
        assert!(!out.additional_context.contains("Commit serially"));
        assert!(!out.additional_context.contains("Unrelated"));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn ordinary_prompts_do_not_inject_gotchas() {
        let workspace = tmp_dir("gotchas-no-match");
        fs::create_dir_all(workspace.join("docs")).unwrap();
        fs::write(
            workspace.join("docs/GOTCHAS.md"),
            "### Archive safely\n**Keys:** task archive\n**Fix:** prove reachability.\n",
        )
        .unwrap();
        let paths = policy_source_paths();
        let out = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                prompt: Some("Explain this function."),
                ..Default::default()
            },
            &paths,
            &PolicyEnv::default(),
        )
        .unwrap();
        assert!(!out.additional_context.contains("Archive safely"));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn gotchas_only_mode_injects_only_keyed_reminder() {
        let workspace = tmp_dir("gotchas-only");
        fs::create_dir_all(workspace.join("docs")).unwrap();
        fs::write(
            workspace.join("docs/GOTCHAS.md"),
            "### Archive safely\n**Keys:** task archive\n**Fix:** prove reachability.\n",
        )
        .unwrap();
        let paths = policy_source_paths();
        let out = build_policy_injection(
            &PolicyInjectionInput {
                workspace: &workspace,
                prompt: Some("task archive"),
                gotchas_only: true,
                ..Default::default()
            },
            &paths,
            &PolicyEnv::default(),
        )
        .unwrap();
        assert!(out.additional_context.contains("Archive safely"));
        assert!(!out.additional_context.contains("Brief is default"));
        assert!(!out.additional_context.contains("MINIMIZE"));
        assert!(!out.additional_context.contains("ccx-mode"));
        assert_eq!(out.system_message, None);
        let _ = fs::remove_dir_all(&workspace);
    }
}
