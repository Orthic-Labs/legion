// Port of `scripts/check-authority-parity.mjs`. `agents/<role>.md`
// frontmatter description and model must match `src/roster/<role>.md`'s
// description and the `claude-code` mapping for its declared model tier;
// `doctrine/<role>.md` must declare no description at all. A tier variant of a
// role (`VARIANTS`, e.g. `alchemist-specialist`) is a second host card of the
// same role: it has its own roster file (`variantOf: <role>`), description and
// tier, but no doctrine of its own; its card embeds the base role's doctrine.

use super::read_json;
use regex::Regex;
use std::fs;
use std::path::Path;

const ROLES: &[&str] = &["sage", "alchemist", "oracle", "sentry"];
const MODEL_HOST: &str = "claude-code";
const CODEX_HOST: &str = "codex";
/// (card id, base role, tier the variant is fixed to).
const VARIANTS: &[(&str, &str, &str)] =
    &[("alchemist-specialist", "alchemist", "balanced-executor")];

/// Every host card: (card id, doctrine it embeds). Roles embed their own doctrine; a variant
/// embeds its base role's.
fn cards() -> Vec<(&'static str, &'static str)> {
    ROLES
        .iter()
        .map(|r| (*r, *r))
        .chain(VARIANTS.iter().map(|(card, base, _)| (*card, *base)))
        .collect()
}

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
        check_card(root, &model_tier_map, role, &mut problems);
    }

    for (variant, base, tier) in VARIANTS {
        check_variant(root, &model_tier_map, variant, base, tier, &mut problems);
        check_card(root, &model_tier_map, variant, &mut problems);
    }

    check_council_seat(root, &model_tier_map, &mut problems);
    check_method_embedded(root, &mut problems);

    problems
}

/// Description parity (agent card vs roster) and model-tier mapping for one host card.
fn check_card(
    root: &Path,
    model_tier_map: &serde_json::Value,
    card: &str,
    problems: &mut Vec<String>,
) {
    let agents_path = root.join(format!("agents/{card}.md"));
    let roster_path = root.join(format!("src/roster/{card}.md"));
    let sources = [
        description(&agents_path, &format!("agents/{card}.md")),
        description(&roster_path, &format!("src/roster/{card}.md")),
    ];
    for source in &sources {
        if let Some(err) = &source.error {
            problems.push(format!("{}: {err}", source.path));
        }
    }
    let values: Vec<&Description> = sources.iter().filter(|s| s.value.is_some()).collect();
    if values.len() != sources.len() {
        return;
    }
    let canonical = values[0];
    for other in &values[1..] {
        if other.value != canonical.value {
            problems.push(format!(
                "{card}: description drift between {} and {}\n  {}: {}\n  {}: {}",
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
                "{card}: no {MODEL_HOST} host model mapping for roster tier '{}' in src/config/model-tiers.json",
                tier.as_deref().unwrap_or("<missing>")
            ));
        }
        Some(expected) => {
            if actual_model.as_deref() != Some(expected) {
                problems.push(format!(
                    "{card}: agents/{card}.md model '{}' does not match the configured {MODEL_HOST} mapping for tier '{}' (expected '{expected}'). Resolve the mapping in src/config/model-tiers.json.",
                    actual_model.as_deref().unwrap_or("<missing>"),
                    tier.as_deref().unwrap_or("<missing>")
                ));
            }
        }
    }
}

fn host_model<'a>(map: &'a serde_json::Value, tier: &str, host: &str) -> Option<&'a str> {
    map.get("tiers")
        .and_then(|v| v.get(tier))
        .and_then(|v| v.get("hosts"))
        .and_then(|v| v.get(host))
        .and_then(|v| v.as_str())
}

/// A variant is a tier variant of one role, never a second role: its roster file names the base
/// role, is fixed to its declared tier (different from the base's), and resolves to different
/// host models than the base on both Claude Code and Codex, or the extra card would be pointless.
fn check_variant(
    root: &Path,
    model_tier_map: &serde_json::Value,
    variant: &str,
    base: &str,
    tier: &str,
    problems: &mut Vec<String>,
) {
    let roster = root.join(format!("src/roster/{variant}.md"));
    let base_roster = root.join(format!("src/roster/{base}.md"));
    if frontmatter_field(&roster, "variantOf").as_deref() != Some(base) {
        problems.push(format!(
            "{variant}: src/roster/{variant}.md must declare `variantOf: {base}`; a variant card shares its base role's doctrine and authority"
        ));
    }
    let declared = frontmatter_field(&roster, "modelTier");
    if declared.as_deref() != Some(tier) {
        problems.push(format!(
            "{variant}: src/roster/{variant}.md modelTier '{}' must be '{tier}'",
            declared.as_deref().unwrap_or("<missing>")
        ));
    }
    let base_tier = frontmatter_field(&base_roster, "modelTier");
    if base_tier.as_deref() == Some(tier) {
        problems.push(format!(
            "{variant}: base role {base} already uses tier '{tier}'; a variant must differ in tier"
        ));
    }
    if let Some(base_tier) = base_tier.as_deref() {
        for host in [MODEL_HOST, CODEX_HOST] {
            let variant_model = host_model(model_tier_map, tier, host);
            let base_model = host_model(model_tier_map, base_tier, host);
            if variant_model.is_none() || variant_model == base_model {
                problems.push(format!(
                    "{variant}: {host} model for tier '{tier}' ({}) must exist and differ from {base}'s tier '{base_tier}' model ({})",
                    variant_model.unwrap_or("<missing>"),
                    base_model.unwrap_or("<missing>")
                ));
            }
        }
    }
    if root.join(format!("doctrine/{variant}.md")).exists() {
        problems.push(format!(
            "{variant}: doctrine/{variant}.md must not exist; the variant embeds doctrine/{base}.md"
        ));
    }
}

fn body_after_frontmatter(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let re = Regex::new(r"(?s)^---\r?\n.*?\r?\n---\r?\n").unwrap();
    let body = re.replace(&text, "").to_string();
    Ok(body.replace("\r\n", "\n").trim().to_string())
}

/// Council seat is not a roster role: its doctrine keeps a frontmatter description (the Codex and
/// Gemini projections read it) and the Claude card must carry the same description, the same body,
/// and the `deliberation` tier model, which no roster role may share.
fn check_council_seat(root: &Path, model_tier_map: &serde_json::Value, problems: &mut Vec<String>) {
    let doctrine = root.join("doctrine/council-seat.md");
    let card = root.join("agents/council-seat.md");
    let doctrine_desc = description(&doctrine, "doctrine/council-seat.md");
    let card_desc = description(&card, "agents/council-seat.md");
    for d in [&doctrine_desc, &card_desc] {
        if let Some(err) = &d.error {
            problems.push(format!("{}: {err}", d.path));
        }
    }
    if let (Some(a), Some(b)) = (&doctrine_desc.value, &card_desc.value) {
        if a != b {
            problems.push(format!(
                "council-seat: description drift between doctrine/council-seat.md and agents/council-seat.md\n  doctrine: {a}\n  card: {b}"
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
                    "council-seat: agents/council-seat.md body differs from doctrine/council-seat.md body; the card must carry the doctrine body verbatim".to_string(),
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
            "council-seat: no {MODEL_HOST} model for tier 'deliberation' in src/config/model-tiers.json"
        )),
        Some(expected) => {
            if actual.as_deref() != Some(expected) {
                problems.push(format!(
                    "council-seat: agents/council-seat.md model '{}' does not match tiers.deliberation.hosts.{MODEL_HOST} ('{expected}')",
                    actual.as_deref().unwrap_or("<missing>")
                ));
            }
            for (role, _) in cards() {
                let role_model = frontmatter_field(&root.join(format!("agents/{role}.md")), "model");
                if role_model.as_deref() == Some(expected) {
                    problems.push(format!(
                        "{role}: agents/{role}.md uses the deliberation model '{expected}', which is reserved for Council seats"
                    ));
                }
            }
        }
    }
}

/// Each role card is self-contained: it carries the doctrine body verbatim under `## Method`, and
/// outside that embedded body it must not point at `doctrine/` or `src/roster/` paths, which the
/// installed plugin does not ship. The doctrine body itself may cross-reference the roster, so the
/// path rule is applied only to card text outside the embedded body.
fn check_method_embedded(root: &Path, problems: &mut Vec<String>) {
    for (role, doctrine_id) in cards() {
        let doctrine = root.join(format!("doctrine/{doctrine_id}.md"));
        let card = root.join(format!("agents/{role}.md"));
        let body = match body_after_frontmatter(&doctrine) {
            Ok(body) => body,
            Err(e) => {
                problems.push(e);
                continue;
            }
        };
        let card_text = match fs::read_to_string(&card) {
            Ok(text) => text.replace("\r\n", "\n"),
            Err(e) => {
                problems.push(format!("{}: {e}", card.display()));
                continue;
            }
        };
        if !card_text.contains(body.as_str()) {
            problems.push(format!(
                "{role}: agents/{role}.md does not contain the doctrine/{doctrine_id}.md body verbatim under ## Method"
            ));
        }
        if let Some((_, base, _)) = VARIANTS.iter().find(|(card_id, _, _)| *card_id == role) {
            for roster_id in [*base, role] {
                match body_after_frontmatter(&root.join(format!("src/roster/{roster_id}.md"))) {
                    Ok(roster_body) if card_text.contains(roster_body.as_str()) => {}
                    Ok(_) => problems.push(format!(
                        "{role}: agents/{role}.md does not contain the src/roster/{roster_id}.md body verbatim under ## Roster"
                    )),
                    Err(e) => problems.push(e),
                }
            }
        }
        let outside = card_text.replacen(body.as_str(), "", 1);
        for forbidden in ["doctrine/", "src/roster/"] {
            if outside.contains(forbidden) {
                problems.push(format!(
                    "{role}: agents/{role}.md refers to `{forbidden}` outside its embedded method; the installed card cannot read that path"
                ));
            }
        }
    }
}

pub fn run(root: &Path) -> bool {
    let problems = check(root);
    if problems.is_empty() {
        println!(
            "authority agent cards match their roster identity ({} cards)",
            ROLES.len() + VARIANTS.len()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn copy_dir(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    /// Copy of the repository inputs the parity check reads, so a test can break one file.
    fn fixture(name: &str) -> std::path::PathBuf {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let root = std::env::temp_dir().join(format!(
            "legion-authority-parity-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        for dir in ["agents", "doctrine", "src/roster", "src/config"] {
            copy_dir(&repo.join(dir), &root.join(dir));
        }
        root
    }

    fn rewrite(path: &Path, from: &str, to: &str) {
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains(from), "{} lacks {from}", path.display());
        fs::write(path, text.replacen(from, to, 1)).unwrap();
    }

    #[test]
    fn shipped_cards_including_the_specialist_variant_pass() {
        let root = fixture("clean");
        let problems = check(&root);
        let _ = fs::remove_dir_all(&root);
        assert!(problems.is_empty(), "{problems:#?}");
    }

    #[test]
    fn specialist_card_on_the_wrong_model_is_rejected() {
        let root = fixture("wrong-model");
        rewrite(
            &root.join("agents/alchemist-specialist.md"),
            "model: sonnet",
            "model: haiku",
        );
        let problems = check(&root);
        let _ = fs::remove_dir_all(&root);
        assert!(
            problems.iter().any(|p| p
                .contains("alchemist-specialist: agents/alchemist-specialist.md model 'haiku'")),
            "{problems:#?}"
        );
    }

    #[test]
    fn base_alchemist_card_must_stay_on_its_own_tier_model() {
        let root = fixture("base-model");
        rewrite(
            &root.join("agents/alchemist.md"),
            "model: haiku",
            "model: sonnet",
        );
        let problems = check(&root);
        let _ = fs::remove_dir_all(&root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("alchemist: agents/alchemist.md model 'sonnet'")),
            "{problems:#?}"
        );
    }

    #[test]
    fn specialist_card_must_carry_the_alchemist_doctrine_body() {
        let root = fixture("body-drift");
        rewrite(
            &root.join("agents/alchemist-specialist.md"),
            "You own one question",
            "You own two questions",
        );
        let problems = check(&root);
        let _ = fs::remove_dir_all(&root);
        assert!(
            problems.iter().any(|p| p.contains("alchemist-specialist: agents/alchemist-specialist.md does not contain the doctrine/alchemist.md body")),
            "{problems:#?}"
        );
    }

    #[test]
    fn variant_roster_must_name_its_base_and_its_fixed_tier() {
        let root = fixture("variant-roster");
        let roster = root.join("src/roster/alchemist-specialist.md");
        rewrite(&roster, "variantOf: alchemist", "variantOf: sage");
        rewrite(
            &roster,
            "modelTier: balanced-executor",
            "modelTier: mechanical-cheap",
        );
        let problems = check(&root);
        let _ = fs::remove_dir_all(&root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("must declare `variantOf: alchemist`")),
            "{problems:#?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("modelTier 'mechanical-cheap' must be 'balanced-executor'")),
            "{problems:#?}"
        );
    }

    #[test]
    fn variant_codex_model_must_differ_from_its_base() {
        let root = fixture("codex-model");
        rewrite(
            &root.join("src/config/model-tiers.json"),
            "\"codex\": \"gpt-6.1-sol\"\n      }\n    },\n    \"mechanical-cheap\"",
            "\"codex\": \"gpt-6-luna\"\n      }\n    },\n    \"mechanical-cheap\"",
        );
        let problems = check(&root);
        let _ = fs::remove_dir_all(&root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("codex model for tier 'balanced-executor'")),
            "{problems:#?}"
        );
    }
}
