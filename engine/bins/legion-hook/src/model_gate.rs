//! Subagent model ceiling for `Agent` / `Task` launches.
//!
//! `src/config/model-tiers.json` is the only place model names live. Its
//! `subagents` block names a ceiling tier, a default tier, the order of the
//! tiers and the approval marker; this module resolves them to the Claude Code
//! model ids in the same file, so the rule cannot drift from the map.
//!
//! A launch whose effective model is above the ceiling is refused unless the
//! launch prompt carries `<marker>: <that model>`. A launch with no model gets
//! the agent card's model when the target is a packaged Legion role, and the
//! default tier's model otherwise.

use serde_json::{Map, Value};

pub(crate) const CEILING_CODE: &str = "ARC_MODEL_CEILING_EXCEEDED";

const MODEL_TIERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../src/config/model-tiers.json"
));

/// Packaged agent cards. Their `model:` line is already held equal to the tier
/// map by `legion-dev check-authority-parity`, so reading it here adds no
/// second source.
const AGENT_CARDS: [(&str, &str); 6] = [
    (
        "alchemist",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../agents/alchemist.md"
        )),
    ),
    (
        "alchemist-specialist",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../agents/alchemist-specialist.md"
        )),
    ),
    (
        "council-seat",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../agents/council-seat.md"
        )),
    ),
    (
        "oracle",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../agents/oracle.md"
        )),
    ),
    (
        "sage",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../agents/sage.md"
        )),
    ),
    (
        "sentry",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../agents/sentry.md"
        )),
    ),
];

#[derive(Debug)]
pub(crate) enum Decision {
    /// Launch as requested.
    Allow,
    /// No model given and none implied: launch with the default tier's model.
    Default {
        updated_input: Value,
        model: String,
    },
    Deny {
        reason: String,
    },
}

#[derive(Debug)]
pub(crate) struct Policy {
    /// `(tier, claude-code model)` from lowest to highest.
    tiers: Vec<(String, String)>,
    ceiling_rank: usize,
    default_model: String,
    ceiling_tier: String,
    ceiling_model: String,
    default_tier: String,
    marker: String,
}

impl Policy {
    pub(crate) fn embedded() -> Result<Self, String> {
        Self::from_source(MODEL_TIERS)
    }

    pub(crate) fn from_source(source: &str) -> Result<Self, String> {
        let document: Value = serde_json::from_str(source).map_err(|error| error.to_string())?;
        let block = document
            .get("subagents")
            .and_then(Value::as_object)
            .ok_or("model-tiers.json has no subagents block")?;
        let text = |key: &str| -> Result<String, String> {
            block
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| format!("subagents.{key} is missing"))
        };
        let host = text("host")?;
        let ceiling_tier = text("ceilingTier")?;
        let default_tier = text("defaultTier")?;
        let marker = text("approvalMarker")?;
        let order = block
            .get("tierOrder")
            .and_then(Value::as_array)
            .ok_or("subagents.tierOrder is missing")?;
        let mut tiers = Vec::new();
        for tier in order {
            let tier = tier
                .as_str()
                .ok_or("subagents.tierOrder holds a non-string")?;
            let model = document
                .pointer(&format!("/tiers/{tier}/hosts/{host}"))
                .and_then(Value::as_str)
                .ok_or_else(|| format!("tier {tier} has no {host} model"))?;
            tiers.push((tier.to_owned(), model.to_owned()));
        }
        let rank_of = |tier: &str| {
            tiers
                .iter()
                .position(|(name, _)| name == tier)
                .ok_or_else(|| format!("tier {tier} is not in subagents.tierOrder"))
        };
        let ceiling_rank = rank_of(&ceiling_tier)?;
        let default_rank = rank_of(&default_tier)?;
        if default_rank > ceiling_rank {
            return Err("the default tier is above the ceiling tier".into());
        }
        Ok(Self {
            default_model: tiers[default_rank].1.clone(),
            ceiling_model: tiers[ceiling_rank].1.clone(),
            tiers,
            ceiling_rank,
            ceiling_tier,
            default_tier,
            marker: marker.to_ascii_lowercase(),
        })
    }

    #[cfg(test)]
    pub(crate) fn default_model(&self) -> &str {
        &self.default_model
    }

    #[cfg(test)]
    pub(crate) fn ceiling_model(&self) -> &str {
        &self.ceiling_model
    }

    #[cfg(test)]
    pub(crate) fn marker(&self) -> &str {
        &self.marker
    }

    /// The tier rank a model string names. The string is read as a list of
    /// names (whitespace and list separators divide them) and every name must
    /// match a tier, so one unrecognised name makes the whole string unknown:
    /// `<known>,<unlisted>` is not judged by its known half. Tiers that
    /// resolve to the same model share the lowest of their ranks (the model is
    /// the same). When the string names several different known models, the
    /// highest wins, so a string that mentions two models is judged by the
    /// stronger. `None` is a model the map does not know (including
    /// `inherit`).
    fn rank(&self, model: &str) -> Option<usize> {
        let lowered = model.to_ascii_lowercase();
        let mut highest = None;
        for name in lowered
            .split(is_model_separator)
            .filter(|name| !name.is_empty())
        {
            highest = highest.max(Some(self.name_rank(name)?));
        }
        highest
    }

    /// The rank of one name: the tier whose host model it contains (ids carry
    /// vendor prefixes and date or context suffixes around the mapped name).
    fn name_rank(&self, name: &str) -> Option<usize> {
        self.tiers
            .iter()
            .filter(|(_, host_model)| name.contains(&host_model.to_ascii_lowercase()))
            .map(|(_, host_model)| {
                self.tiers
                    .iter()
                    .position(|(_, other)| other == host_model)
                    .unwrap_or(usize::MAX)
            })
            .max()
    }

    fn within_ceiling(&self, model: &str) -> bool {
        self.rank(model)
            .is_some_and(|rank| rank <= self.ceiling_rank)
    }

    /// Does the launch prompt carry `<marker>: <model>` on a line of its own?
    fn approved(&self, prompt: &str, model: &str) -> bool {
        let wanted = model.trim().to_ascii_lowercase();
        prompt.lines().any(|line| {
            let line = line
                .trim()
                .trim_start_matches(['-', '*', '>', ' '])
                .to_ascii_lowercase();
            let Some(rest) = line.strip_prefix(&self.marker) else {
                return false;
            };
            let Some(value) = rest.trim_start().strip_prefix([':', '=']) else {
                return false;
            };
            value.trim().trim_matches(['`', '"', '\'']) == wanted
        })
    }

    pub(crate) fn evaluate(&self, input: &Map<String, Value>) -> Decision {
        let text = |key: &str| {
            input
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        };
        let prompt = text("prompt").unwrap_or("");
        let requested = text("model");
        let card = text("subagent_type").and_then(agent_card_model);

        let (effective, source) = match (requested, card) {
            (Some(model), _) => (model.to_owned(), "requested"),
            (None, Some(model)) => (model, "agent card"),
            (None, None) => {
                let mut updated = input.clone();
                updated.insert("model".into(), Value::String(self.default_model.clone()));
                return Decision::Default {
                    updated_input: Value::Object(updated),
                    model: self.default_model.clone(),
                };
            }
        };
        if self.within_ceiling(&effective) || self.approved(prompt, &effective) {
            return Decision::Allow;
        }
        Decision::Deny {
            reason: format!(
                "Agent/Task launch refused: the {source} model '{effective}' is above the subagent ceiling (tier '{ceiling_tier}', '{ceiling_model}'; default tier '{default_tier}', '{default_model}'). Relaunch with model '{default_model}' or '{ceiling_model}'. Only when the operator named this model in the live turn, add the line '{marker}: {effective}' to the launch prompt. Rule: skills/dispatch/references/agent-routing.md; models: src/config/model-tiers.json.",
                ceiling_tier = self.ceiling_tier,
                ceiling_model = self.ceiling_model,
                default_tier = self.default_tier,
                default_model = self.default_model,
                marker = self.marker,
            ),
        }
    }
}

/// What divides the names in a model string: whitespace, list separators and
/// quoting. Model ids themselves use letters, digits and `-_.:/@[]`.
fn is_model_separator(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            ',' | ';' | '|' | '+' | '&' | '(' | ')' | '"' | '\'' | '`'
        )
}

/// `legion:oracle`, `oracle` and `plugin:legion:oracle` all name the card.
fn agent_card_model(subagent_type: &str) -> Option<String> {
    let name = subagent_type
        .rsplit(':')
        .next()
        .unwrap_or(subagent_type)
        .trim()
        .to_ascii_lowercase();
    let (_, card) = AGENT_CARDS.iter().find(|(id, _)| *id == name)?;
    frontmatter_model(card)
}

fn frontmatter_model(card: &str) -> Option<String> {
    let body = card.replace("\r\n", "\n");
    let body = body.strip_prefix("---\n")?;
    let (frontmatter, _) = body.split_once("\n---")?;
    frontmatter.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "model").then(|| value.trim().to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy() -> Policy {
        Policy::embedded().expect("embedded tier map has a subagents block")
    }

    /// Tier model names come from the map, never from this file.
    fn tier_model(policy: &Policy, tier: &str) -> String {
        policy
            .tiers
            .iter()
            .find(|(name, _)| name == tier)
            .map(|(_, model)| model.clone())
            .unwrap_or_else(|| panic!("tier {tier} missing"))
    }

    fn launch(model: Option<&str>, subagent: Option<&str>, prompt: &str) -> Map<String, Value> {
        let mut input = json!({"description": "d", "prompt": prompt});
        if let Some(model) = model {
            input["model"] = json!(model);
        }
        if let Some(subagent) = subagent {
            input["subagent_type"] = json!(subagent);
        }
        input.as_object().unwrap().clone()
    }

    #[test]
    fn tiers_at_or_below_the_ceiling_launch_as_requested() {
        let policy = policy();
        for tier in ["mechanical-cheap", "balanced-executor"] {
            let model = tier_model(&policy, tier);
            assert!(
                matches!(
                    policy.evaluate(&launch(Some(&model), Some("general-purpose"), "work")),
                    Decision::Allow
                ),
                "{tier}"
            );
        }
    }

    #[test]
    fn tiers_above_the_ceiling_are_refused_and_the_reason_names_the_rule() {
        let policy = policy();
        // Sage and Oracle run frontier-judgment, which resolves to the ceiling
        // model on this host: they are never held by the ceiling.
        assert!(policy.within_ceiling(&tier_model(&policy, "frontier-judgment")));
        {
            let tier = "deliberation";
            let model = tier_model(&policy, tier);
            let Decision::Deny { reason } =
                policy.evaluate(&launch(Some(&model), Some("general-purpose"), "work"))
            else {
                panic!("{tier} must be refused");
            };
            assert!(reason.contains(&model), "{reason}");
            assert!(reason.contains("agent-routing.md"), "{reason}");
            assert!(reason.contains(policy.marker()), "{reason}");
        }
    }

    #[test]
    fn the_approval_marker_must_name_the_same_model() {
        let policy = policy();
        let high = tier_model(&policy, "deliberation");
        let other = "an-unlisted-model".to_owned();
        let approved = format!("Review this.\n{}: {high}\n", policy.marker());
        assert!(matches!(
            policy.evaluate(&launch(Some(&high), None, &approved)),
            Decision::Allow
        ));
        // Approval for one model does not cover another.
        assert!(matches!(
            policy.evaluate(&launch(Some(&other), None, &approved)),
            Decision::Deny { .. }
        ));
        // The marker mid-sentence is not a marker line.
        let prose = format!("please note {}: {high} is fine", policy.marker());
        assert!(matches!(
            policy.evaluate(&launch(Some(&high), None, &prose)),
            Decision::Deny { .. }
        ));
        // Any case, quoted value.
        let shouty = format!("{}: `{}`", policy.marker().to_ascii_uppercase(), high);
        assert!(matches!(
            policy.evaluate(&launch(Some(&high), None, &shouty)),
            Decision::Allow
        ));
    }

    #[test]
    fn unknown_and_inherited_models_are_refused() {
        let policy = policy();
        for model in ["inherit", "some-new-model", "default"] {
            assert!(
                matches!(
                    policy.evaluate(&launch(Some(model), None, "work")),
                    Decision::Deny { .. }
                ),
                "{model}"
            );
        }
    }

    #[test]
    fn a_string_naming_two_models_is_judged_by_the_stronger() {
        let policy = policy();
        let low = tier_model(&policy, "mechanical-cheap");
        let high = tier_model(&policy, "deliberation");
        let both = format!("{low}-then-{high}");
        assert!(matches!(
            policy.evaluate(&launch(Some(&both), None, "work")),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn a_model_string_with_any_unrecognised_name_is_unknown() {
        let policy = policy();
        let low = tier_model(&policy, "mechanical-cheap");
        let mid = tier_model(&policy, "balanced-executor");
        let unlisted = "an-unlisted-model";
        for model in [
            format!("{low},{unlisted}"),
            format!("{low}, {unlisted}"),
            format!("{low} {unlisted}"),
            format!("{unlisted} {low}"),
            format!("{low};{unlisted}"),
            format!("{mid}|{unlisted}"),
            format!("({low}) {unlisted}"),
            format!("{mid}\t{unlisted}"),
        ] {
            assert_eq!(policy.rank(&model), None, "{model}");
            assert!(
                matches!(
                    policy.evaluate(&launch(Some(&model), Some("general-purpose"), "work")),
                    Decision::Deny { .. }
                ),
                "{model}"
            );
        }
        // An unrecognised name does not hide behind a recognised one on a
        // launch whose card names no model either.
        assert!(matches!(
            policy.evaluate(&launch(Some(unlisted), None, "work")),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn recognised_names_keep_their_vendor_decorations_and_the_stronger_wins() {
        let policy = policy();
        let low = tier_model(&policy, "mechanical-cheap");
        let mid = tier_model(&policy, "balanced-executor");
        let high = tier_model(&policy, "deliberation");
        let low_rank = policy.rank(&low).expect("the cheap tier ranks");
        let mid_rank = policy.rank(&mid).expect("the balanced tier ranks");
        for model in [
            format!("vendor-{low}-4-5-20251001"),
            format!("{low}[1m]"),
            format!("provider/{low}:0"),
            format!("\"{low}\""),
            format!("  {low}  "),
        ] {
            assert_eq!(policy.rank(&model), Some(low_rank), "{model}");
            assert!(policy.within_ceiling(&model), "{model}");
        }
        for model in [format!("{low},{mid}"), format!("{low} {mid}")] {
            assert_eq!(policy.rank(&model), Some(mid_rank), "{model}");
        }
        assert!(!policy.within_ceiling(&format!("{low},{high}")));
        assert_eq!(policy.rank(""), None);
        assert_eq!(policy.rank(" , "), None);
    }

    #[test]
    fn a_launch_with_no_model_gets_the_default_unless_a_legion_role_implies_one() {
        let policy = policy();
        let Decision::Default {
            updated_input,
            model,
        } = policy.evaluate(&launch(None, Some("general-purpose"), "look something up"))
        else {
            panic!("a generic launch with no model takes the default");
        };
        assert_eq!(model, policy.default_model());
        assert_eq!(updated_input["model"], json!(policy.default_model()));
        // The rest of the input is carried over unchanged.
        assert_eq!(updated_input["prompt"], json!("look something up"));
        assert_eq!(updated_input["subagent_type"], json!("general-purpose"));

        // No subagent_type at all is the same.
        assert!(matches!(
            policy.evaluate(&launch(None, None, "x")),
            Decision::Default { .. }
        ));

        // Packaged roles keep the model their card declares.
        for role in [
            "legion:alchemist",
            "legion:alchemist-specialist",
            "legion:oracle",
            "legion:sage",
            "sentry",
        ] {
            assert!(
                matches!(
                    policy.evaluate(&launch(None, Some(role), "x")),
                    Decision::Allow
                ),
                "{role} card must sit at or under the ceiling"
            );
        }
    }

    #[test]
    fn a_card_above_the_ceiling_needs_the_marker_even_with_no_model_given() {
        let policy = policy();
        // The council seat is the one packaged card on the deliberation tier.
        let seat = agent_card_model("legion:council-seat").expect("card has a model");
        assert!(!policy.within_ceiling(&seat));
        let Decision::Deny { reason } =
            policy.evaluate(&launch(None, Some("legion:council-seat"), "packet"))
        else {
            panic!("an above-ceiling card must be refused");
        };
        assert!(reason.contains("agent card"), "{reason}");
        let approved = format!("{}: {seat}", policy.marker());
        assert!(matches!(
            policy.evaluate(&launch(None, Some("legion:council-seat"), &approved)),
            Decision::Allow
        ));
    }

    #[test]
    fn the_ceiling_and_default_come_from_the_map_and_are_ordered() {
        let policy = policy();
        assert_eq!(
            policy.default_model(),
            tier_model(&policy, "mechanical-cheap")
        );
        assert_eq!(
            policy.ceiling_model(),
            tier_model(&policy, "balanced-executor")
        );
        assert!(Policy::from_source(r#"{"tiers":{}}"#).is_err());
        let inverted = MODEL_TIERS.replace(
            "\"defaultTier\": \"mechanical-cheap\"",
            "\"defaultTier\": \"deliberation\"",
        );
        assert!(Policy::from_source(&inverted).is_err());
    }
}
