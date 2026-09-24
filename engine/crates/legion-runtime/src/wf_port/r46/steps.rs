//! Port of the execution-step validator from `validate-dispatch.py`:
//! `STEP_LABELS`, `STEP_RE`, `exact_action_validator_path_errors()`, and
//! `step_errors()` (lines ~814, ~856, ~1012-1157).

use super::dependency::parse_dependency_contract;
use super::labels::{action_re, bound_re, fenced_value_after, is_concrete, path_re};
use super::route_scan::label_value;
use super::tables::table_rows;
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

pub const STEP_LABELS: &[&str] = &[
    "**Route step:**",
    "**Advances target:**",
    "**Dependency order:**",
    "**Purpose:**",
    "**Inputs:**",
    "**Working directory:**",
    "**Exact action / command:**",
    "**Expected stdout / state:**",
    "**Expected exit / result:**",
    "**Timeout / retry:**",
    "**Output artifacts:**",
    "**Evidence to record:**",
    "**On failure:**",
];

fn step_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^### Step\s+\d+\s+—\s+.+$").unwrap())
}

fn validator_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)validate-dispatch\.py").unwrap())
}

fn dollar_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$([A-Za-z_]\w*)").unwrap())
}

fn assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?im)^\s*\$([A-Za-z_]\w*)\s*=\s*(\S+)").unwrap())
}

fn relative_assignment_value_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)^["']?(?:tasks|tools)[\\/]"#).unwrap())
}

fn relative_invocation_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:^|\s)(?:tasks|tools)[\\/]").unwrap())
}

fn route_step_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^ROUTE_STEP:([A-Z][A-Z0-9_-]*)/([A-Z][A-Z0-9_-]*)$").unwrap())
}

/// Port of `exact_action_validator_path_errors()`.
pub fn exact_action_validator_path_errors(name: &str, action: &str) -> Vec<String> {
    let invocation_lines: Vec<&str> = action.lines().filter(|l| validator_line_re().is_match(l)).collect();
    if invocation_lines.is_empty() {
        return Vec::new();
    }
    let invocation_variables: HashSet<String> = invocation_lines
        .iter()
        .flat_map(|line| dollar_var_re().captures_iter(line).map(|c| c.get(1).unwrap().as_str().to_lowercase()))
        .collect();
    let relative_assignment = assignment_re().captures_iter(action).any(|caps| {
        let var = caps.get(1).unwrap().as_str().to_lowercase();
        let value = caps.get(2).unwrap().as_str();
        invocation_variables.contains(&var) && relative_assignment_value_re().is_match(value)
    });
    let relative_invocation = invocation_lines.iter().any(|line| relative_invocation_re().is_match(line));
    if relative_assignment || relative_invocation {
        vec![format!("{name} exact action uses checkout-relative validator paths")]
    } else {
        Vec::new()
    }
}

/// Port of `step_errors()`.
pub fn step_errors(text: &str, allow_template: bool) -> Vec<String> {
    let matches: Vec<regex::Match> = step_re().find_iter(text).collect();
    if matches.is_empty() {
        return vec!["missing execution step: expected '### Step N — name'".to_string()];
    }

    let mut errors = Vec::new();
    let section_end = text.find("## 6. Failure Decision & Recovery Matrix");
    let mut selected_route = label_value(text, "**Selected route:**").unwrap_or_default();
    selected_route = selected_route.trim_matches('`').to_string();
    if let Some(stripped) = Regex::new(r"(?i)^SELECTED_ROUTE:\s*").unwrap().find(&selected_route) {
        selected_route = selected_route[stripped.end()..].to_string();
    }
    let mut seen_route_steps: BTreeSet<String> = BTreeSet::new();
    let mut execution_dependencies: HashMap<String, BTreeSet<String>> = HashMap::new();

    for (index, m) in matches.iter().enumerate() {
        let end = matches.get(index + 1).map(|next| next.start()).or(section_end).unwrap_or(text.len());
        let block = &text[m.start()..end];
        let name = m.as_str();
        for label in STEP_LABELS {
            if !block.contains(label) {
                errors.push(format!("{name} missing label: {label}"));
            }
        }
        let action = fenced_value_after(block, "**Exact action / command:**");
        if action.is_none() {
            errors.push(format!("{name} missing fenced exact action/command"));
        }
        if !allow_template {
            for label in STEP_LABELS {
                if *label == "**Exact action / command:**" {
                    continue;
                }
                let value = label_value(block, label);
                let concrete = value.as_deref().map(is_concrete).unwrap_or(false);
                if value.is_none() || !concrete {
                    errors.push(format!("{name} has non-concrete value: {label}"));
                }
            }
            let cwd = label_value(block, "**Working directory:**").unwrap_or_default();
            if !path_re().is_match(&cwd) {
                errors.push(format!("{name} working directory is not an explicit path"));
            }
            if let Some(action) = &action {
                if !is_concrete(action) || !action_re().is_match(action) {
                    errors.push(format!("{name} exact action is not executable/actionable"));
                }
                errors.extend(exact_action_validator_path_errors(name, action));
            }
            let timeout = label_value(block, "**Timeout / retry:**").unwrap_or_default();
            if !bound_re().is_match(&timeout) {
                errors.push(format!("{name} timeout/retry lacks numeric bound"));
            }
            for label in ["**Output artifacts:**", "**Evidence to record:**"] {
                let value = label_value(block, label).unwrap_or_default();
                if !path_re().is_match(&value) {
                    errors.push(format!("{name} {label} lacks explicit artifact path"));
                }
            }
            let route_step = label_value(block, "**Route step:**").unwrap_or_default();
            match route_step_re().captures(&route_step) {
                None => errors.push(format!("{name} lacks exact ROUTE_STEP binding")),
                Some(route_match) => {
                    let route_id = route_match.get(1).unwrap().as_str().to_string();
                    let step_id = format!("{route_id}/{}", route_match.get(2).unwrap().as_str()).to_uppercase();
                    if !selected_route.is_empty()
                        && route_id.to_lowercase() != selected_route.to_lowercase()
                    {
                        errors.push(format!("{name} binds non-selected route"));
                    }
                    let dependency = label_value(block, "**Dependency order:**").unwrap_or_default();
                    if Regex::new(r"(?i)^START:\s*\S").unwrap().is_match(&dependency) {
                        execution_dependencies.insert(step_id.clone(), BTreeSet::new());
                    } else if let Some(dependency_match) = Regex::new(r"(?i)^AFTER:\s*(\S.+)$").unwrap().captures(&dependency) {
                        let deps: BTreeSet<String> = Regex::new(r"[,+]")
                            .unwrap()
                            .split(dependency_match.get(1).unwrap().as_str())
                            .map(|s| s.trim().to_uppercase())
                            .filter(|s| !s.is_empty())
                            .collect();
                        let unknown: Vec<&String> = deps.difference(&seen_route_steps).collect();
                        if !unknown.is_empty() {
                            let mut sorted: Vec<String> = unknown.into_iter().cloned().collect();
                            sorted.sort();
                            errors.push(format!(
                                "{name} dependency order references future/unknown route step: {}",
                                sorted.join(", ")
                            ));
                        }
                        execution_dependencies.insert(step_id.clone(), deps);
                    } else {
                        errors.push(format!("{name} dependency order must be START or AFTER prior route step"));
                    }
                    seen_route_steps.insert(step_id);
                }
            }
            let advances = label_value(block, "**Advances target:**").unwrap_or_default();
            if !Regex::new(r"(?i)^ADVANCES_STATE_B:\s*\S").unwrap().is_match(&advances) {
                errors.push(format!("{name} lacks observable ADVANCES_STATE_B delta"));
            }
        }
    }

    if !allow_template {
        let route_table = table_rows(text, "## 1C. Goal Route & Critical Path", "## 1D. Experiment Topology & Workload Funnel");
        let selected_rows: Vec<&Vec<String>> = route_table
            .iter()
            .skip(1)
            .filter(|row| row.len() == 11 && row[9].trim_matches('`').to_uppercase() == "SELECTED")
            .collect();
        if selected_rows.len() == 1 {
            let row = selected_rows[0];
            let declared_steps: BTreeSet<String> = if let Some(caps) = Regex::new(r"(?i)^STEPS:(.+)$").unwrap().captures(&row[1]) {
                caps.get(1).unwrap().as_str().split('>').map(|s| s.trim().to_uppercase()).collect()
            } else {
                BTreeSet::new()
            };
            if declared_steps != seen_route_steps {
                errors.push("execution step bindings must exactly cover selected route steps".to_string());
            }
            if let Some((roots, edges)) = parse_dependency_contract(&row[2]) {
                let mut expected_dependencies: HashMap<String, BTreeSet<String>> = HashMap::new();
                for step in &declared_steps {
                    let deps: BTreeSet<String> = edges
                        .iter()
                        .filter(|(_, target)| target == step)
                        .map(|(source, _)| source.clone())
                        .collect();
                    expected_dependencies.insert(step.clone(), deps);
                }
                for root in &roots {
                    expected_dependencies.entry(root.clone()).or_default();
                }
                if execution_dependencies != expected_dependencies {
                    errors.push("execution dependency bindings must exactly match selected route DAG".to_string());
                }
            }
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_step_reports_expected_message() {
        let errors = step_errors("no steps here", false);
        assert_eq!(errors, vec!["missing execution step: expected '### Step N — name'".to_string()]);
    }

    #[test]
    fn exact_action_flags_relative_invocation() {
        let action = "run python tasks/validate-dispatch.py --check";
        let errors = exact_action_validator_path_errors("### Step 1 — x", action);
        assert_eq!(errors, vec!["### Step 1 — x exact action uses checkout-relative validator paths".to_string()]);
    }

    #[test]
    fn exact_action_ignores_unrelated_command() {
        let action = "cargo run --bin rightkit";
        assert!(exact_action_validator_path_errors("### Step 1 — x", action).is_empty());
    }

    #[test]
    fn step_present_but_missing_labels_reports_them() {
        let text = "### Step 1 — do the thing\nsome body\n";
        let errors = step_errors(text, true);
        assert!(errors.iter().any(|e| e.contains("missing label: **Route step:**")));
    }
}
