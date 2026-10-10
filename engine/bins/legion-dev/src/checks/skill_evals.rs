// Structural gate for the skill-eval corpus (`skills/**/evals/*.json`).
//
// Port of the deterministic half of the deleted `scripts/run-skill-evals.mjs`
// (removed in ebb349ae). It validates structure only. Routing and behaviour
// grading needs a model and cannot run in CI, so every such case is reported
// as `requires-model` and is never counted as passed.
//
// Checks:
//   1. JSON parses; trigger fixtures carry `schema_version`, `skill`, and all
//      six case arrays (`should_trigger`, `should_not_trigger`,
//      `output_quality`, `safety`, `pressure`, `compatibility`);
//   2. each case has `id` (unique per file), `prompt`, `expected_behavior`,
//      valid `severity`/`mode`/`assertions`/`routing` shapes;
//   3. skill names (`skill`, `route`, `expected_skill`, `forbidden_skills`,
//      assertion skill values, `routing.firstRankedCapability`) resolve to a
//      packaged skill or specialist; retired names are allowed only as
//      negative routing targets;
//   4. fixture paths named by a case (`fixture`, `fixtures`, `fixture_path`,
//      `files`) exist;
//   5. no string (outside explanatory note keys) names a deleted proof: a
//      missing `.mjs`/`.cjs` file or a missing repository file under a known
//      root such as `scripts/`;
//   6. at least one `should_trigger` prompt shares a keyword with the skill's
//      name or SKILL.md text.
// Files without the category arrays (specification-only data) get checks 1
// (parse) and 5 only; `model_free` entries with `proof: "unwired"` are
// counted as unwired, never as passed.

use super::{read_text, tracked_files};
use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const CATEGORIES: [&str; 6] = [
    "should_trigger",
    "should_not_trigger",
    "output_quality",
    "safety",
    "pressure",
    "compatibility",
];
/// Optional extra arrays that hold ordinary cases.
const EXTRA_CASE_ARRAYS: [&str; 1] = ["human_quality"];
const SEVERITIES: [&str; 3] = ["error", "warning", "info"];
const MODES: [&str; 5] = ["discovery", "output", "runtime", "static", "human"];
const AUTHORITIES: [&str; 3] = ["sage", "alchemist", "oracle"];
const ROUTE_MODES: [&str; 2] = ["DIRECT", "MACHINERY"];
const SEMANTIC: [&str; 3] = ["FORBIDDEN", "CONDITIONAL", "REQUIRED"];
/// Skills that no longer exist but still appear as negative routing targets
/// ("this prompt must not go to the old X"). Allowed in `forbidden_skills`
/// and as `expected_skill` of a `should_not_trigger` case only.
const RETIRED_ROUTE_TARGETS: [&str; 10] = [
    "jury",
    "doctor",
    "execution-preflight",
    "plan",
    "review",
    "hormozi",
    "website",
    "canon",
    "compshop",
    "writing-pro",
];
/// Keys whose text explains history and may name deleted files.
const NOTE_KEYS: [&str; 4] = ["proof_note", "engine_status", "_note", "legacy_skill"];

#[derive(Debug, Default)]
pub struct Report {
    pub issues: Vec<String>,
    pub files: usize,
    pub trigger_files: usize,
    pub spec_files: usize,
    pub cases: usize,
    pub requires_model: usize,
    pub unwired: usize,
}

pub fn is_eval_file(path: &str) -> bool {
    path.starts_with("skills/")
        && path.ends_with(".json")
        && path.rsplit('/').nth(1) == Some("evals")
}

fn owner_dir(path: &str) -> &str {
    path.rsplit_once("/evals/").map(|(d, _)| d).unwrap_or("")
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Every skill and specialist name a fixture may legitimately point at.
pub fn known_names(files: &[String]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for file in files.iter().filter(|f| f.starts_with("skills/")) {
        let segs: Vec<&str> = file.split('/').collect();
        if segs.last() == Some(&"SKILL.md") && segs.len() >= 2 {
            names.insert(segs[segs.len() - 2].to_string());
        }
        for (i, seg) in segs.iter().enumerate() {
            if (*seg == "specialists" || *seg == "references") && i + 2 < segs.len() {
                names.insert(segs[i + 1].to_string());
            }
        }
        if is_eval_file(file) {
            names.insert(basename(owner_dir(file)).to_string());
        }
    }
    names
}

fn nonempty(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

fn string_array(v: &Value) -> Option<Vec<&str>> {
    v.as_array()?.iter().map(Value::as_str).collect()
}

struct Ctx<'a> {
    root: &'a Path,
    owner: String,
    known: &'a BTreeSet<String>,
}

impl Ctx<'_> {
    fn skill_issue(&self, name: &str, allow_retired: bool) -> Option<String> {
        if self.known.contains(name) || (allow_retired && RETIRED_ROUTE_TARGETS.contains(&name)) {
            None
        } else if RETIRED_ROUTE_TARGETS.contains(&name) {
            Some(format!(
                "retired skill `{name}` is allowed only in forbidden_skills or as a should_not_trigger expected_skill"
            ))
        } else {
            Some(format!(
                "unknown skill `{name}` (no packaged skill or specialist has that name)"
            ))
        }
    }

    fn path_exists(&self, rel: &str) -> bool {
        let owner = Path::new(&self.owner);
        self.root.join(rel).exists()
            || self.root.join(owner).join(rel).exists()
            || self.root.join(owner).join("evals").join(rel).exists()
    }
}

fn check_routing(routing: &Value, loc: &str, ctx: &Ctx, issues: &mut Vec<String>) {
    let Some(obj) = routing.as_object() else {
        issues.push(format!("{loc}: routing must be an object"));
        return;
    };
    for key in ["shouldRoute", "should_route"] {
        if let Some(v) = obj.get(key) {
            if !v.is_boolean() {
                issues.push(format!("{loc}: routing.{key} must be boolean"));
            }
        }
    }
    for key in ["firstRankedCapability", "first_ranked_capability"] {
        match obj.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => {
                if let Some(issue) = ctx.skill_issue(s, false) {
                    issues.push(format!("{loc}: routing.{key}: {issue}"));
                }
            }
            Some(_) => issues.push(format!("{loc}: routing.{key} must be a string or null")),
        }
    }
    if let Some(auth) = obj.get("authority") {
        let ok = match auth {
            Value::Array(items) => {
                let names: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
                let unique: BTreeSet<&str> = names.iter().copied().collect();
                names.len() == items.len()
                    && names.iter().all(|n| AUTHORITIES.contains(n))
                    && unique.len() == names.len()
            }
            Value::Object(map) => AUTHORITIES
                .iter()
                .all(|a| map.get(*a).map(Value::is_boolean).unwrap_or(false)),
            _ => false,
        };
        if !ok {
            issues.push(format!(
                "{loc}: routing.authority must be a unique array of sage/alchemist/oracle or an object of three booleans"
            ));
        }
    }
    if let Some(v) = obj.get("routeMode") {
        if !v
            .as_str()
            .map(|s| ROUTE_MODES.contains(&s))
            .unwrap_or(false)
        {
            issues.push(format!(
                "{loc}: routing.routeMode must be DIRECT or MACHINERY"
            ));
        }
    }
    if let Some(v) = obj.get("semanticRequirement") {
        if !v.as_str().map(|s| SEMANTIC.contains(&s)).unwrap_or(false) {
            issues.push(format!(
                "{loc}: routing.semanticRequirement must be FORBIDDEN, CONDITIONAL, or REQUIRED"
            ));
        }
    }
    if let Some(ctxsel) = obj.get("contextSelection") {
        let ok = match ctxsel {
            Value::Array(_) => string_array(ctxsel).is_some(),
            Value::Object(map) => ["required", "forbidden", "selected"].iter().all(|k| {
                map.get(*k)
                    .map(|v| string_array(v).is_some())
                    .unwrap_or(true)
            }),
            _ => false,
        };
        if !ok {
            issues.push(format!(
                "{loc}: routing.contextSelection must be an array of strings or an object of string arrays"
            ));
        }
    }
}

fn check_case(category: &str, loc: &str, entry: &Value, ctx: &Ctx, issues: &mut Vec<String>) {
    let Some(obj) = entry.as_object() else {
        issues.push(format!("{loc}: case must be an object"));
        return;
    };
    for key in ["id", "prompt", "expected_behavior"] {
        if !nonempty(obj.get(key)) {
            issues.push(format!("{loc}: missing or empty {key}"));
        }
    }
    let negative = category == "should_not_trigger";
    let mut expected: Option<&str> = None;
    match obj.get("expected_skill") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => {
            expected = Some(s.as_str());
            if let Some(issue) = ctx.skill_issue(s, negative) {
                issues.push(format!("{loc}: expected_skill: {issue}"));
            }
        }
        Some(_) => issues.push(format!("{loc}: expected_skill must be a string or null")),
    }
    if let Some(forbidden) = obj.get("forbidden_skills") {
        match string_array(forbidden) {
            None => issues.push(format!(
                "{loc}: forbidden_skills must be an array of strings"
            )),
            Some(names) => {
                for name in &names {
                    if let Some(issue) = ctx.skill_issue(name, true) {
                        issues.push(format!("{loc}: forbidden_skills: {issue}"));
                    }
                }
                if let Some(e) = expected {
                    if names.contains(&e) {
                        issues.push(format!(
                            "{loc}: expected_skill `{e}` is also listed in forbidden_skills"
                        ));
                    }
                }
            }
        }
    }
    if let Some(v) = obj.get("severity") {
        if !v.as_str().map(|s| SEVERITIES.contains(&s)).unwrap_or(false) {
            issues.push(format!(
                "{loc}: severity {v} is outside {}",
                SEVERITIES.join("|")
            ));
        }
    }
    if let Some(v) = obj.get("mode") {
        if !v.as_str().map(|s| MODES.contains(&s)).unwrap_or(false) {
            issues.push(format!("{loc}: mode {v} is outside {}", MODES.join("|")));
        }
    }
    if let Some(assertions) = obj.get("assertions") {
        match assertions.as_array() {
            Some(list) if !list.is_empty() => {
                for (i, a) in list.iter().enumerate() {
                    let aloc = format!("{loc}#assertions.{i}");
                    match a {
                        Value::String(s) if !s.trim().is_empty() => {}
                        Value::Object(map) => {
                            if !nonempty(map.get("type")) || !map.contains_key("value") {
                                issues.push(format!("{aloc}: assertion needs a non-empty type and a value"));
                                continue;
                            }
                            let kind = map["type"].as_str().unwrap_or("");
                            if kind == "expected_skill" || kind == "forbidden_skill" {
                                match map["value"].as_str() {
                                    // null means "no skill is expected"
                                    None if kind == "expected_skill" && map["value"].is_null() => {}
                                    None => issues.push(format!("{aloc}: {kind} value must be a string")),
                                    Some(name) => {
                                        let allow = kind == "forbidden_skill" || negative;
                                        if let Some(issue) = ctx.skill_issue(name, allow) {
                                            issues.push(format!("{aloc}: {issue}"));
                                        }
                                        if kind == "expected_skill" {
                                            if let Some(e) = expected {
                                                if e != name {
                                                    issues.push(format!(
                                                        "{aloc}: expected_skill assertion `{name}` disagrees with case expected_skill `{e}`"
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => issues.push(format!("{aloc}: assertion must be a non-empty string or a {{type, value}} object")),
                    }
                }
            }
            _ => issues.push(format!("{loc}: assertions must be a non-empty array")),
        }
    }
    if let Some(routing) = obj.get("routing") {
        check_routing(routing, loc, ctx, issues);
    }
    for key in ["fixture", "fixtures", "fixture_path", "files"] {
        let Some(v) = obj.get(key) else { continue };
        let paths: Vec<&str> = match v {
            Value::String(s) => vec![s.as_str()],
            Value::Array(_) => match string_array(v) {
                Some(p) => p,
                None => {
                    issues.push(format!(
                        "{loc}: {key} must be a string or an array of strings"
                    ));
                    continue;
                }
            },
            _ => {
                issues.push(format!(
                    "{loc}: {key} must be a string or an array of strings"
                ));
                continue;
            }
        };
        for p in paths {
            if !ctx.path_exists(p) {
                issues.push(format!("{loc}: {key} names `{p}`, which does not exist"));
            }
        }
    }
}

fn collect_strings<'a>(value: &'a Value, out: &mut Vec<&'a str>) {
    match value {
        Value::String(s) => out.push(s),
        Value::Array(items) => items.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(map) => {
            for (k, v) in map {
                if !NOTE_KEYS.contains(&k.as_str()) {
                    collect_strings(v, out);
                }
            }
        }
        _ => {}
    }
}

fn check_deleted_proofs(rel: &str, doc: &Value, ctx: &Ctx, issues: &mut Vec<String>) {
    let mut strings = Vec::new();
    collect_strings(doc, &mut strings);
    let re = Regex::new(
        r"(?:\b(?:scripts|tools|bench|docs|doctrine|hooks)/[A-Za-z0-9_./-]*[A-Za-z0-9_]\.[A-Za-z0-9]+\b)|(?:[A-Za-z0-9_./-]+\.(?:mjs|cjs)\b)",
    )
    .unwrap();
    let mut seen = BTreeSet::new();
    for text in strings {
        for m in re.find_iter(text) {
            let token = m.as_str().trim_end_matches('.');
            if seen.insert(token.to_string()) && !ctx.path_exists(token) {
                issues.push(format!(
                    "{rel}: names `{token}`, which does not exist (deleted proof or script?)"
                ));
            }
        }
    }
}

fn keyword_set(text: &str) -> BTreeSet<String> {
    let re = Regex::new(r"[a-z][a-z-]{4,}").unwrap();
    re.find_iter(&text.to_lowercase())
        .map(|m| m.as_str().to_string())
        .collect()
}

fn skill_text(root: &Path, owner: &str, label: &str, stem: &str) -> String {
    let stem = if stem == "evals" { "" } else { stem };
    let mut text = format!("{owner} {label} {stem}").replace('/', " ");
    let mut dir = owner.to_string();
    while dir.starts_with("skills/") {
        if let Some(body) = read_text(&root.join(&dir).join("SKILL.md")) {
            text.push(' ');
            text.push_str(&body);
        }
        dir = match dir.rsplit_once('/') {
            Some((parent, _)) => parent.to_string(),
            None => break,
        };
    }
    text
}

fn is_trigger_fixture(doc: &Value) -> bool {
    doc.as_object()
        .map(|o| CATEGORIES.iter().any(|c| o.contains_key(*c)))
        .unwrap_or(false)
}

fn check_route_field(rel: &str, doc: &Value, ctx: &Ctx, issues: &mut Vec<String>) {
    let Some(route) = doc.get("route") else {
        return;
    };
    let Some(route) = route.as_str() else {
        issues.push(format!("{rel}: route must be a string"));
        return;
    };
    match route.split_once(':') {
        Some(("capability", name)) => {
            if let Some(issue) = ctx.skill_issue(name, false) {
                issues.push(format!("{rel}: route: {issue}"));
            }
        }
        Some(("authority", name)) if AUTHORITIES.contains(&name) => {}
        _ => issues.push(format!(
            "{rel}: route `{route}` must be capability:<skill> or authority:<sage|alchemist|oracle>"
        )),
    }
}

fn check_document(rel: &str, doc: &Value, ctx: &Ctx, report: &mut Report) {
    check_deleted_proofs(rel, doc, ctx, &mut report.issues);
    if !is_trigger_fixture(doc) {
        report.spec_files += 1;
        if let Some(entries) = doc.get("model_free").and_then(Value::as_array) {
            for (i, entry) in entries.iter().enumerate() {
                let loc = format!("{rel}#model_free.{i}");
                if !nonempty(entry.get("id")) || !nonempty(entry.get("expected")) {
                    report
                        .issues
                        .push(format!("{loc}: needs non-empty id and expected"));
                }
                match entry.get("proof").and_then(Value::as_str) {
                    Some("unwired") => report.unwired += 1,
                    Some(_) => {}
                    None => report.issues.push(format!("{loc}: missing proof")),
                }
            }
        }
        return;
    }
    report.trigger_files += 1;
    let stem = basename(rel).trim_end_matches(".json");
    let issues = &mut report.issues;
    if !doc
        .get("schema_version")
        .map(Value::is_number)
        .unwrap_or(false)
    {
        issues.push(format!("{rel}: missing numeric schema_version"));
    }
    let label = doc.get("skill").and_then(Value::as_str).unwrap_or("");
    if label.trim().is_empty() {
        issues.push(format!("{rel}: missing skill"));
    } else if let Some(issue) = ctx.skill_issue(label, false) {
        issues.push(format!("{rel}: skill: {issue}"));
    }
    check_route_field(rel, doc, ctx, issues);

    let mut seen_ids = BTreeSet::new();
    let mut triggers = 0usize;
    let mut negatives = 0usize;
    for category in CATEGORIES.iter().chain(EXTRA_CASE_ARRAYS.iter()) {
        let required = CATEGORIES.contains(category);
        let Some(value) = doc.get(*category) else {
            if required {
                issues.push(format!(
                    "{rel}#{category}: must be an array (present, possibly empty)"
                ));
            }
            continue;
        };
        let Some(entries) = value.as_array() else {
            issues.push(format!("{rel}#{category}: must be an array"));
            continue;
        };
        if *category == "should_trigger" {
            triggers = entries.len();
        }
        if *category == "should_not_trigger" {
            negatives = entries.len();
        }
        for (i, entry) in entries.iter().enumerate() {
            report.cases += 1;
            report.requires_model += 1;
            let loc = format!("{rel}#{category}.{i}");
            check_case(category, &loc, entry, ctx, issues);
            if let Some(id) = entry.get("id").and_then(Value::as_str) {
                if !seen_ids.insert(id.to_string()) {
                    issues.push(format!("{loc}: duplicate id {id}"));
                }
            }
        }
    }
    if triggers == 0 && negatives == 0 {
        issues.push(format!(
            "{rel}: no trigger coverage (should_trigger and should_not_trigger both empty)"
        ));
    }
    if triggers > 0 {
        let keywords = keyword_set(&skill_text(ctx.root, &ctx.owner, label, stem));
        let hit = doc["should_trigger"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|e| {
                let prompt = e.get("prompt").and_then(Value::as_str).unwrap_or("");
                keyword_set(prompt).intersection(&keywords).next().is_some()
            });
        if !hit {
            issues.push(format!(
                "{rel}: no should_trigger prompt shares a keyword with the skill name or SKILL.md"
            ));
        }
    }
}

/// Validate `files` (repository-relative paths); only eval JSON files are read.
pub fn check_files(root: &Path, files: &[String]) -> Report {
    let known = known_names(files);
    let mut report = Report::default();
    let mut evals: Vec<&String> = files.iter().filter(|f| is_eval_file(f)).collect();
    evals.sort();
    for rel in evals {
        report.files += 1;
        let text = match std::fs::read_to_string(root.join(rel)) {
            Ok(t) => t,
            Err(e) => {
                report.issues.push(format!("{rel}: unreadable ({e})"));
                continue;
            }
        };
        let doc: Value = match serde_json::from_str(&text) {
            Ok(d) => d,
            Err(e) => {
                report.issues.push(format!("{rel}: invalid JSON ({e})"));
                continue;
            }
        };
        if !doc.is_object() {
            report
                .issues
                .push(format!("{rel}: fixture must be a JSON object"));
            continue;
        }
        let ctx = Ctx {
            root,
            owner: owner_dir(rel).to_string(),
            known: &known,
        };
        check_document(rel, &doc, &ctx, &mut report);
    }
    report.issues.sort();
    report
}

pub fn run(root: &Path) -> bool {
    let files = tracked_files(root);
    let report = check_files(root, &files);
    if report.files == 0 {
        eprintln!("check-skill-evals: no skills/**/evals/*.json files found");
        return false;
    }
    if !report.issues.is_empty() {
        for issue in &report.issues {
            eprintln!("{issue}");
        }
        eprintln!(
            "\ncheck-skill-evals failed: {} issue(s) across {} eval files",
            report.issues.len(),
            report.files
        );
        return false;
    }
    println!(
        "skill evals structurally valid: {} files ({} trigger fixtures, {} specification-only), {} cases",
        report.files, report.trigger_files, report.spec_files, report.cases
    );
    println!(
        "requires-model: {} cases in {} fixtures (routing and behaviour grading is not run in CI; none of these are counted as passed)",
        report.requires_model, report.trigger_files
    );
    if report.unwired > 0 {
        println!(
            "unwired: {} specification entries have no runner (not counted as passed)",
            report.unwired
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(label: &str) -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "legion-skillevals-{label}-{}-{nonce}-{}",
                std::process::id(),
                {
                    static NEXT: ::std::sync::atomic::AtomicU64 =
                        ::std::sync::atomic::AtomicU64::new(0);
                    NEXT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed)
                }
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn write(&self, rel: &str, body: &str) {
            let path = self.0.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }
        fn run(&self) -> Report {
            let files: Vec<String> = walkdir::WalkDir::new(&self.0)
                .into_iter()
                .flatten()
                .filter(|e| e.file_type().is_file())
                .filter_map(|e| {
                    e.path()
                        .strip_prefix(&self.0)
                        .ok()
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                })
                .collect();
            check_files(&self.0, &files)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn case(id: &str, extra: &str) -> String {
        format!(
            r#"{{"id":"{id}","prompt":"please review the database migration","expected_behavior":"does the thing"{extra}}}"#
        )
    }

    fn doc(skill: &str, trigger: &str, negative: &str) -> String {
        format!(
            r#"{{"schema_version":1,"skill":"{skill}","should_trigger":[{trigger}],"should_not_trigger":[{negative}],
"output_quality":[],"safety":[],"pressure":[],"compatibility":[]}}"#
        )
    }

    fn base(fx: &Fixture) {
        fx.write(
            "skills/alpha/SKILL.md",
            "---\nname: alpha\n---\nReview database migrations.\n",
        );
        fx.write(
            "skills/beta/SKILL.md",
            "---\nname: beta\n---\nBeta things.\n",
        );
    }

    #[test]
    fn valid_fixture_passes_and_counts_requires_model() {
        let fx = Fixture::new("valid");
        base(&fx);
        fx.write(
            "skills/alpha/evals/evals.json",
            &doc(
                "alpha",
                &case("a-1", r#","expected_skill":"alpha""#),
                &case(
                    "a-2",
                    r#","expected_skill":"beta","severity":"error","mode":"human""#,
                ),
            ),
        );
        let report = fx.run();
        assert!(report.issues.is_empty(), "{:?}", report.issues);
        assert_eq!(report.trigger_files, 1);
        assert_eq!(report.cases, 2);
        assert_eq!(report.requires_model, 2);
    }

    #[test]
    fn missing_category_array_and_bad_json_fail() {
        let fx = Fixture::new("shape");
        base(&fx);
        fx.write(
            "skills/alpha/evals/evals.json",
            r#"{"schema_version":1,"skill":"alpha","should_trigger":[],"should_not_trigger":[]}"#,
        );
        fx.write("skills/beta/evals/evals.json", "{not json");
        let report = fx.run();
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("alpha/evals/evals.json#safety")));
        assert!(report.issues.iter().any(|i| i.contains("invalid JSON")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.contains("no trigger coverage")));
    }

    #[test]
    fn unknown_and_retired_skill_names_are_distinguished() {
        let fx = Fixture::new("names");
        base(&fx);
        fx.write(
            "skills/alpha/evals/evals.json",
            &doc(
                "alpha",
                &case(
                    "a-1",
                    r#","expected_skill":"ghost","forbidden_skills":["jury"]"#,
                ),
                &case("a-2", r#","expected_skill":"plan""#),
            ),
        );
        let report = fx.run();
        let text = report.issues.join("\n");
        assert!(text.contains("unknown skill `ghost`"), "{text}");
        // retired name is fine in forbidden_skills and as a negative expected_skill
        assert!(!text.contains("`jury`"), "{text}");
        assert!(!text.contains("`plan`"), "{text}");
        let fx = Fixture::new("retired-positive");
        base(&fx);
        fx.write(
            "skills/alpha/evals/evals.json",
            &doc(
                "alpha",
                &case("a-1", r#","expected_skill":"plan""#),
                &case("a-2", ""),
            ),
        );
        assert!(fx
            .run()
            .issues
            .iter()
            .any(|i| i.contains("retired skill `plan`")));
    }

    #[test]
    fn duplicate_ids_and_self_contradiction_fail() {
        let fx = Fixture::new("dup");
        base(&fx);
        fx.write(
            "skills/alpha/evals/evals.json",
            &doc(
                "alpha",
                &case(
                    "same",
                    r#","expected_skill":"alpha","forbidden_skills":["alpha"]"#,
                ),
                &case("same", ""),
            ),
        );
        let text = fx.run().issues.join("\n");
        assert!(text.contains("duplicate id same"), "{text}");
        assert!(text.contains("also listed in forbidden_skills"), "{text}");
    }

    #[test]
    fn assertion_and_routing_shapes_are_validated() {
        let fx = Fixture::new("routing");
        base(&fx);
        let bad = case(
            "a-1",
            r#","expected_skill":"alpha","assertions":[{"type":"expected_skill","value":"beta"},{"type":"x"}],"routing":{"routeMode":"SIDEWAYS","authority":["king"],"shouldRoute":"yes"}"#,
        );
        fx.write(
            "skills/alpha/evals/evals.json",
            &doc("alpha", &bad, &case("a-2", "")),
        );
        let text = fx.run().issues.join("\n");
        assert!(
            text.contains("disagrees with case expected_skill"),
            "{text}"
        );
        assert!(
            text.contains("needs a non-empty type and a value"),
            "{text}"
        );
        assert!(text.contains("routing.routeMode"), "{text}");
        assert!(text.contains("routing.authority"), "{text}");
        assert!(
            text.contains("routing.shouldRoute must be boolean"),
            "{text}"
        );
    }

    #[test]
    fn missing_fixture_file_fails_and_present_one_passes() {
        let fx = Fixture::new("fixture");
        base(&fx);
        fx.write("skills/alpha/evals/data/input.txt", "x");
        fx.write(
            "skills/alpha/evals/evals.json",
            &doc(
                "alpha",
                &case(
                    "a-1",
                    r#","fixtures":["data/input.txt","data/missing.txt"]"#,
                ),
                &case("a-2", ""),
            ),
        );
        let text = fx.run().issues.join("\n");
        assert!(text.contains("data/missing.txt"), "{text}");
        assert!(!text.contains("data/input.txt"), "{text}");
    }

    #[test]
    fn deleted_proof_references_fail_but_notes_and_prose_do_not() {
        let fx = Fixture::new("proofs");
        base(&fx);
        let with_proof = case(
            "a-1",
            r#","assertions":["runs council.test.mjs and scripts/gone.sh"]"#,
        );
        let prose = r#"{"id":"a-2","prompt":"discover current tools/version/schema","expected_behavior":"ok"}"#;
        let mut document = doc("alpha", &with_proof, prose);
        document = document.replacen(
            "{\"schema_version\":1,",
            "{\"schema_version\":1,\"proof_note\":\"was council.test.mjs\",",
            1,
        );
        fx.write("skills/alpha/evals/evals.json", &document);
        let text = fx.run().issues.join("\n");
        assert!(text.contains("council.test.mjs"), "{text}");
        assert!(text.contains("scripts/gone.sh"), "{text}");
        assert_eq!(
            text.matches("council.test.mjs").count(),
            1,
            "note key must be skipped: {text}"
        );
        assert!(!text.contains("tools/version"), "{text}");
    }

    #[test]
    fn keyword_coverage_requires_one_related_trigger_prompt() {
        let fx = Fixture::new("keywords");
        base(&fx);
        let unrelated = r#"{"id":"a-1","prompt":"bake sourdough bread","expected_behavior":"x"}"#;
        fx.write(
            "skills/alpha/evals/evals.json",
            &doc("alpha", unrelated, &case("a-2", "")),
        );
        assert!(fx
            .run()
            .issues
            .iter()
            .any(|i| i.contains("shares a keyword")));
    }

    #[test]
    fn specification_files_are_not_counted_as_cases_and_unwired_is_reported() {
        let fx = Fixture::new("spec");
        base(&fx);
        fx.write(
            "skills/alpha/evals/spec.json",
            r#"{"model_free":[{"id":"M-1","proof":"unwired","expected":"x"},{"id":"M-2","expected":"y"}]}"#,
        );
        let report = fx.run();
        assert_eq!(report.spec_files, 1);
        assert_eq!(report.cases, 0);
        assert_eq!(report.unwired, 1);
        assert!(report.issues.iter().any(|i| i.contains("missing proof")));
    }

    #[test]
    fn route_field_and_fixture_label_must_resolve() {
        let fx = Fixture::new("route");
        base(&fx);
        let mut document = doc("nobody", &case("a-1", ""), &case("a-2", ""));
        document = document.replacen(
            "{\"schema_version\":1,",
            "{\"schema_version\":1,\"route\":\"capability:ghost\",",
            1,
        );
        fx.write("skills/alpha/evals/evals.json", &document);
        let text = fx.run().issues.join("\n");
        assert!(text.contains("skill: unknown skill `nobody`"), "{text}");
        assert!(text.contains("route: unknown skill `ghost`"), "{text}");
    }

    #[test]
    fn eval_file_detection_only_matches_json_directly_under_evals() {
        assert!(is_eval_file("skills/a/specialists/b/evals/evals.json"));
        assert!(!is_eval_file("skills/a/evals/README.md"));
        assert!(!is_eval_file("skills/a/evals/sub/x.json"));
        assert!(!is_eval_file("docs/evals/x.json"));
    }
}
