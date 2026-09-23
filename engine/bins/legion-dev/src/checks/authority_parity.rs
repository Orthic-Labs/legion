// Port of `scripts/check-authority-parity.mjs`. `agents/<role>.md`
// frontmatter description and model must match `src/roster/<role>.md`'s
// description and the `claude-code` mapping for its declared model tier;
// `doctrine/<role>.md` must declare no description at all.

use super::read_json;
use regex::Regex;
use std::fs;
use std::path::Path;

const ROLES: &[&str] = &["sage", "alchemist", "oracle"];
const MODEL_HOST: &str = "claude-code";

struct Frontmatter {
    body: Option<String>,
}

fn frontmatter(path: &Path) -> Result<Frontmatter, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let re = Regex::new(r"(?s)^---\r?\n(.*?)\r?\n---").unwrap();
    Ok(Frontmatter {
        body: re.captures(&text).map(|c| c[1].to_string()),
    })
}

fn field(frontmatter_body: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?m)^{name}:[ \t]*(.+)$")).unwrap();
    re.captures(frontmatter_body).map(|c| c[1].trim().to_string())
}

struct Description {
    path: String,
    value: Option<String>,
    error: Option<String>,
}

fn description(path: &Path, rel: &str) -> Description {
    let fm = match frontmatter(path) {
        Ok(fm) => fm,
        Err(e) => {
            return Description {
                path: rel.to_string(),
                value: None,
                error: Some(e),
            }
        }
    };
    let Some(body) = fm.body else {
        return Description {
            path: rel.to_string(),
            value: None,
            error: Some("missing frontmatter".to_string()),
        };
    };
    match field(&body, "description") {
        Some(v) => {
            let normalized = Regex::new(r"\s+").unwrap().replace_all(&v, " ").to_string();
            Description {
                path: rel.to_string(),
                value: Some(normalized),
                error: None,
            }
        }
        None => Description {
            path: rel.to_string(),
            value: None,
            error: Some("missing frontmatter description".to_string()),
        },
    }
}

fn declares_description(path: &Path) -> bool {
    match frontmatter(path) {
        Ok(fm) => match fm.body {
            Some(body) => field(&body, "description").is_some(),
            None => false,
        },
        Err(_) => false,
    }
}

fn frontmatter_field(path: &Path, name: &str) -> Option<String> {
    let fm = frontmatter(path).ok()?;
    field(&fm.body?, name)
}

pub fn check(root: &Path) -> Vec<String> {
    let mut problems = Vec::new();

    let model_tier_map = match read_json(&root.join("src/config/model-tiers.json")) {
        Ok(v) => v,
        Err(e) => {
            problems.push(format!("src/config/model-tiers.json: {e}"));
            return problems;
        }
    };

    for role in ROLES {
        let doctrine_path = root.join(format!("doctrine/{role}.md"));
        if declares_description(&doctrine_path) {
            problems.push(format!(
                "{role}: doctrine/{role}.md declares a frontmatter description. Nothing consumes it, so it can only drift. Delete the key; src/roster/{role}.md is the canonical description and doctrine carries its method in the body."
            ));
        }

        let agents_path = root.join(format!("agents/{role}.md"));
        let roster_path = root.join(format!("src/roster/{role}.md"));
        let sources = [
            description(&agents_path, &format!("agents/{role}.md")),
            description(&roster_path, &format!("src/roster/{role}.md")),
        ];
        for source in &sources {
            if let Some(err) = &source.error {
                problems.push(format!("{}: {err}", source.path));
            }
        }
        let values: Vec<&Description> = sources.iter().filter(|s| s.value.is_some()).collect();
        if values.len() != sources.len() {
            continue;
        }
        let canonical = values[0];
        for other in &values[1..] {
            if other.value != canonical.value {
                problems.push(format!(
                    "{role}: description drift between {} and {}\n  {}: {}\n  {}: {}",
                    canonical.path,
                    other.path,
                    canonical.path,
                    canonical.value.as_deref().unwrap_or(""),
                    other.path,
                    other.value.as_deref().unwrap_or("")
                ));
            }
        }

        let tier = frontmatter_field(&roster_path, "modelTier");
        let expected_model = tier.as_ref().and_then(|t| {
            model_tier_map
                .get("tiers")
                .and_then(|v| v.get(t))
                .and_then(|v| v.get("hosts"))
                .and_then(|v| v.get(MODEL_HOST))
                .and_then(|v| v.as_str())
        });
        let actual_model = frontmatter_field(&agents_path, "model");
        match expected_model {
            None => {
                problems.push(format!(
                    "{role}: no {MODEL_HOST} host model mapping for roster tier '{}' in src/config/model-tiers.json",
                    tier.as_deref().unwrap_or("<missing>")
                ));
            }
            Some(expected) => {
                if actual_model.as_deref() != Some(expected) {
                    problems.push(format!(
                        "{role}: agents/{role}.md model '{}' does not match the configured {MODEL_HOST} mapping for tier '{}' (expected '{expected}'). Resolve the mapping in src/config/model-tiers.json.",
                        actual_model.as_deref().unwrap_or("<missing>"),
                        tier.as_deref().unwrap_or("<missing>")
                    ));
                }
            }
        }
    }

    problems
}

pub fn run(root: &Path) -> bool {
    let problems = check(root);
    if problems.is_empty() {
        println!(
            "authority agent cards match their roster identity ({} roles)",
            ROLES.len()
        );
        true
    } else {
        eprintln!("authority description parity failed:");
        for problem in &problems {
            eprintln!("- {problem}");
        }
        false
    }
}
