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
    re.captures(frontmatter_body)
        .map(|c| c[1].trim().to_string())
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

    check_covenant_seat(root, &model_tier_map, &mut problems);

    problems
}

fn body_after_frontmatter(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let re = Regex::new(r"(?s)^---\r?\n.*?\r?\n---\r?\n").unwrap();
    let body = re.replace(&text, "").to_string();
    Ok(body.replace("\r\n", "\n").trim().to_string())
}

/// Covenant seat is not a roster role: its doctrine keeps a frontmatter description (the Codex and
/// Gemini projections read it) and the Claude card must carry the same description, the same body,
/// and the `deliberation` tier model, which no roster role may share.
fn check_covenant_seat(
    root: &Path,
    model_tier_map: &serde_json::Value,
    problems: &mut Vec<String>,
) {
    let doctrine = root.join("doctrine/covenant-seat.md");
    let card = root.join("agents/covenant-seat.md");
    let doctrine_desc = description(&doctrine, "doctrine/covenant-seat.md");
    let card_desc = description(&card, "agents/covenant-seat.md");
    for d in [&doctrine_desc, &card_desc] {
        if let Some(err) = &d.error {
            problems.push(format!("{}: {err}", d.path));
        }
    }
    if let (Some(a), Some(b)) = (&doctrine_desc.value, &card_desc.value) {
        if a != b {
            problems.push(format!(
                "covenant-seat: description drift between doctrine/covenant-seat.md and agents/covenant-seat.md\n  doctrine: {a}\n  card: {b}"
            ));
        }
    }
    match (
        body_after_frontmatter(&doctrine),
        body_after_frontmatter(&card),
    ) {
        (Ok(a), Ok(b)) => {
            if a != b {
                problems.push(
                    "covenant-seat: agents/covenant-seat.md body differs from doctrine/covenant-seat.md body; the card must carry the doctrine body verbatim".to_string(),
                );
            }
        }
        (Err(e), _) | (_, Err(e)) => problems.push(e),
    }
    let deliberation = model_tier_map
        .get("tiers")
        .and_then(|v| v.get("deliberation"))
        .and_then(|v| v.get("hosts"))
        .and_then(|v| v.get(MODEL_HOST))
        .and_then(|v| v.as_str());
    let actual = frontmatter_field(&card, "model");
    match deliberation {
        None => problems.push(format!(
            "covenant-seat: no {MODEL_HOST} model for tier 'deliberation' in src/config/model-tiers.json"
        )),
        Some(expected) => {
            if actual.as_deref() != Some(expected) {
                problems.push(format!(
                    "covenant-seat: agents/covenant-seat.md model '{}' does not match tiers.deliberation.hosts.{MODEL_HOST} ('{expected}')",
                    actual.as_deref().unwrap_or("<missing>")
                ));
            }
            for role in ROLES {
                let role_model = frontmatter_field(&root.join(format!("agents/{role}.md")), "model");
                if role_model.as_deref() == Some(expected) {
                    problems.push(format!(
                        "{role}: agents/{role}.md uses the deliberation model '{expected}', which is reserved for Covenant seats"
                    ));
                }
            }
        }
    }
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
