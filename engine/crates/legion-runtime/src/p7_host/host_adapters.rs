//! Port of src/lib/host/adapters/{claude-code,cline,codex,command-code,
//! generic,pi}.mjs. These are static descriptor data in JS; ported here as
//! functions returning the equivalent JSON so the shape (and any future
//! consumer that walks `surfaces`) matches exactly.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub fn claude_code_descriptor() -> Value {
    json!({
        "id": "claude-code", "displayName": "Claude Code", "installOwner": "plugin",
        "detect": {"anyOf": [".claude", ".claude-plugin/plugin.json", "CLAUDE.md"]},
        "surfaces": {
            "instructions": {"fidelity": "strong", "mechanism": {"kind": "plugin"}, "note": "CLAUDE.md + plugin doctrine"},
            "skills": {"fidelity": "strong", "mechanism": {"kind": "plugin"}, "note": "plugin ships skills/ natively"},
            "agents": {"fidelity": "strong", "mechanism": {"kind": "plugin"}, "note": "plugin ships agents/ natively"},
            "mcp": {"fidelity": "strong", "mechanism": {"kind": "plugin"}, "note": "legion MCP server in plugin.json"},
            "hooks": {"fidelity": "strong", "mechanism": {"kind": "blocking-hook"}, "note": "Guard pre/post-tool hooks in hooks.json"},
        },
    })
}

pub fn cline_descriptor() -> Value {
    json!({
        "id": "cline", "displayName": "Cline", "installOwner": "adapter",
        "detect": {"anyOf": [".clinerules"], "env": ["CLINE_ACTIVE"]},
        "surfaces": {
            "instructions": {"fidelity": "strong", "mechanism": {"kind": "native-file", "path": ".clinerules/legion.md"}},
            "skills": {"fidelity": "degraded", "mechanism": {"kind": "skills-dir", "path": ".agents/skills"}, "note": "no native skill discovery; canonical packages projected to .agents/skills and referenced from .clinerules"},
            "agents": {"fidelity": "unsupported", "mechanism": {"kind": "none"}, "note": "no native subagent primitive"},
            "mcp": {"fidelity": "unsupported", "mechanism": {"kind": "none"}, "note": "MCP registry is extension-managed (cline_mcp_settings.json), outside the repo; Legion does not install it"},
            "hooks": {"fidelity": "unsupported", "mechanism": {"kind": "none"}, "note": "no blocking effect gate"},
        },
    })
}

pub fn codex_descriptor() -> Value {
    json!({
        "id": "codex", "displayName": "Codex", "installOwner": "adapter",
        "detect": {"anyOf": [".codex", ".codex/config.toml"], "env": ["CODEX_HOME", "CODEX_THREAD_ID", "CODEX_SESSION_ID"]},
        "surfaces": {
            "instructions": {"fidelity": "strong", "mechanism": {"kind": "agents-md", "path": "AGENTS.md"}},
            "skills": {"fidelity": "strong", "mechanism": {"kind": "skills-dir", "path": ".agents/skills"}, "note": "native Agent Skills discovery with generated implicit/explicit invocation policy"},
            "agents": {"fidelity": "unsupported", "mechanism": {"kind": "none"}, "note": "no native subagents"},
            "mcp": {"fidelity": "strong", "mechanism": {"kind": "toml", "path": ".codex/config.toml", "table": "mcp_servers"}},
            "hooks": {"fidelity": "unsupported", "mechanism": {"kind": "none"}, "note": "no effect-enforcement hook surface; Guard enforcement is absent, not degraded"},
        },
    })
}

pub fn command_code_descriptor() -> Value {
    json!({
        "id": "command-code", "displayName": "Command Code", "installOwner": "adapter",
        "detect": {"anyOf": [".commandcode", ".command-code"], "env": ["COMMAND_CODE_HOME"]},
        "surfaces": {
            "instructions": {"fidelity": "strong", "mechanism": {"kind": "agents-md", "path": "AGENTS.md"}},
            "skills": {"fidelity": "degraded", "mechanism": {"kind": "skills-dir", "path": ".agents/skills"}, "note": "no verified native skill discovery; canonical packages projected to .agents/skills and referenced from AGENTS.md"},
            "agents": {"fidelity": "unsupported", "mechanism": {"kind": "none"}, "note": "native subagent support unconfirmed for this harness"},
            "mcp": {"fidelity": "unsupported", "mechanism": {"kind": "none"}, "note": "MCP registration path unconfirmed for this harness"},
            "hooks": {"fidelity": "unsupported", "mechanism": {"kind": "none"}},
        },
    })
}

pub fn pi_descriptor() -> Value {
    json!({
        "id": "pi", "displayName": "Pi", "installOwner": "adapter",
        "detect": {"anyOf": [".pi", ".pi/config"], "env": ["PI_HOME", "PI_SESSION"]},
        "surfaces": {
            "instructions": {"fidelity": "strong", "mechanism": {"kind": "agents-md", "path": "AGENTS.md"}},
            "skills": {"fidelity": "degraded", "mechanism": {"kind": "skills-dir", "path": ".agents/skills"}, "note": "no verified native skill discovery; canonical packages projected to .agents/skills and referenced from AGENTS.md"},
            "agents": {"fidelity": "unsupported", "mechanism": {"kind": "none"}, "note": "native subagent support unconfirmed for this harness"},
            "mcp": {"fidelity": "unsupported", "mechanism": {"kind": "none"}, "note": "MCP registration path unconfirmed for this harness"},
            "hooks": {"fidelity": "unsupported", "mechanism": {"kind": "none"}},
        },
    })
}

fn generic_default() -> Value {
    json!({
        "id": "generic", "displayName": "Generic / custom harness", "installOwner": "adapter",
        "surfaces": {
            "instructions": {"fidelity": "strong", "mechanism": {"kind": "agents-md", "path": "AGENTS.md"}},
            "skills": {"fidelity": "degraded", "mechanism": {"kind": "skills-dir", "path": ".agents/skills"}, "note": "canonical packages projected to .agents/skills and referenced from the instructions block"},
            "agents": {"fidelity": "unsupported", "mechanism": {"kind": "none"}},
            "mcp": {"fidelity": "unsupported", "mechanism": {"kind": "none"}},
            "hooks": {"fidelity": "unsupported", "mechanism": {"kind": "none"}},
        },
    })
}

#[derive(Debug, thiserror::Error)]
#[error("harness descriptor at {path} {message}")]
pub struct HarnessDescriptorError {
    pub path: String,
    pub message: String,
}

/// Port of `resolveGenericDescriptor`. `read_file` is injected so callers can
/// supply real filesystem access; a missing candidate is skipped exactly as
/// `existsSync` gates it in JS.
pub fn resolve_generic_descriptor(
    root: &Path,
    env: &HashMap<String, String>,
    read_file: &dyn Fn(&Path) -> Option<String>,
) -> Result<Value, HarnessDescriptorError> {
    let from_env = env.get("LEGION_HARNESS_DESCRIPTOR");
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = from_env {
        let path = Path::new(p);
        candidates.push(if path.is_absolute() { path.to_path_buf() } else { root.join(path) });
    }
    candidates.push(root.join(".agents").join("legion-harness.json"));

    for path in candidates {
        let Some(contents) = read_file(&path) else { continue };
        let declared: Value = serde_json::from_str(&contents).map_err(|e| HarnessDescriptorError {
            path: path.display().to_string(),
            message: format!("does not parse: {e}"),
        })?;
        if !declared.is_object() {
            return Err(HarnessDescriptorError {
                path: path.display().to_string(),
                message: "must be a JSON object".to_string(),
            });
        }
        let mut merged = generic_default();
        let declared_obj = declared.as_object().cloned().unwrap_or_default();
        if let Value::Object(base) = &mut merged {
            for (k, v) in declared_obj.iter() {
                if k == "surfaces" {
                    let over_surfaces = v.as_object().cloned().unwrap_or_default();
                    if let Some(Value::Object(base_surfaces)) = base.get_mut("surfaces") {
                        for (sk, sv) in over_surfaces.iter() {
                            base_surfaces.insert(sk.clone(), sv.clone());
                        }
                    }
                } else {
                    base.insert(k.clone(), v.clone());
                }
            }
        }
        merged["source"] = json!(path.display().to_string());
        return Ok(merged);
    }
    let mut default = generic_default();
    default["source"] = json!("built-in default");
    Ok(default)
}

pub fn generic_descriptor() -> Value {
    let mut d = generic_default();
    d["detect"] = json!({"env": ["LEGION_HARNESS", "LEGION_HARNESS_DESCRIPTOR"]});
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_code_declares_full_native_fidelity() {
        let d = claude_code_descriptor();
        assert_eq!(d["surfaces"]["hooks"]["fidelity"], "strong");
        assert_eq!(d["installOwner"], "plugin");
    }

    #[test]
    fn cline_declares_mcp_unsupported() {
        let d = cline_descriptor();
        assert_eq!(d["surfaces"]["mcp"]["fidelity"], "unsupported");
    }

    #[test]
    fn codex_declares_strong_mcp_via_toml() {
        let d = codex_descriptor();
        assert_eq!(d["surfaces"]["mcp"]["mechanism"]["kind"], "toml");
    }

    #[test]
    fn resolve_generic_descriptor_falls_back_to_default_when_nothing_found() {
        let env = HashMap::new();
        let result = resolve_generic_descriptor(Path::new("/repo"), &env, &|_| None).unwrap();
        assert_eq!(result["source"], "built-in default");
        assert_eq!(result["id"], "generic");
    }

    #[test]
    fn resolve_generic_descriptor_merges_declared_surfaces_over_default() {
        let env = HashMap::new();
        let declared = r#"{"surfaces": {"mcp": {"fidelity": "strong", "mechanism": {"kind": "json"}}}}"#;
        let result = resolve_generic_descriptor(Path::new("/repo"), &env, &|p| {
            if p.ends_with("legion-harness.json") { Some(declared.to_string()) } else { None }
        })
        .unwrap();
        assert_eq!(result["surfaces"]["mcp"]["fidelity"], "strong");
        // instructions surface retained from default (declared didn't override it)
        assert_eq!(result["surfaces"]["instructions"]["fidelity"], "strong");
    }

    #[test]
    fn resolve_generic_descriptor_errors_on_malformed_json() {
        let env = HashMap::new();
        let result = resolve_generic_descriptor(Path::new("/repo"), &env, &|p| {
            if p.ends_with("legion-harness.json") { Some("{not json".to_string()) } else { None }
        });
        assert!(result.is_err());
    }
}
