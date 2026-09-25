// Port of `scripts/check-release-obligations.mjs`. Validates
// `release/obligations.json`: every gate's obligations name a real evidence
// producer (a package script, a file, or a recognized artifact-name
// pattern), unimplemented obligations name a gap and no evidence, ids are
// unique, and each of the three capability grants is owned by exactly one
// gate.

use super::read_json;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;

const GRANTS: &[&str] = &["BUILD_AUTHORIZED", "SIGNING_AUTHORIZED", "RELEASE_AUTHORIZED"];

pub struct Report {
    pub ok: bool,
    pub issues: Vec<String>,
}

fn artifact_pattern() -> Regex {
    Regex::new(r"(?i)^[a-z0-9-]+(\.json|-summary| readback| fetch)$").unwrap()
}

pub fn check(root: &Path) -> Report {
    let path = root.join("release/obligations.json");
    if !path.is_file() {
        return Report {
            ok: false,
            issues: vec!["release/obligations.json is missing".to_string()],
        };
    }
    let manifest = match read_json(&path) {
        Ok(v) => v,
        Err(e) => {
            return Report {
                ok: false,
                issues: vec![format!("release/obligations.json is invalid JSON: {e}")],
            }
        }
    };

    let mut issues = Vec::new();
    let identity_ok = manifest.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1)
        && manifest.get("kind").and_then(|v| v.as_str()) == Some("legion-release-obligations")
        && manifest.get("product").and_then(|v| v.as_str()) == Some("legion");
    if !identity_ok {
        issues.push("release obligations manifest identity is invalid".to_string());
    }

    let empty = Vec::new();
    let gates = manifest.get("gates").and_then(|v| v.as_array()).unwrap_or(&empty);
    if gates.is_empty() {
        issues.push("release obligations manifest declares no gates".to_string());
        return Report { ok: false, issues };
    }

    let scripts = match read_json(&root.join("package.json")) {
        Ok(v) => v.get("scripts").cloned().unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };
    let has_script = |name: &str| -> bool {
        scripts.get(name).and_then(|v| v.as_str()).is_some()
    };

    let mut seen_gates: HashSet<String> = HashSet::new();
    let mut seen_obligations: HashSet<String> = HashSet::new();
    let artifact_re = artifact_pattern();

    for gate in gates {
        let gate_id = gate.get("id").and_then(|v| v.as_str());
        let gate_name = gate.get("name").and_then(|v| v.as_str());
        let (gate_id, _gate_name) = match (gate_id, gate_name) {
            (Some(i), Some(n)) => (i, n),
            _ => {
                issues.push("a gate is missing id or name".to_string());
                continue;
            }
        };
        if !seen_gates.insert(gate_id.to_string()) {
            issues.push(format!("duplicate gate id: {gate_id}"));
        }
        let grant = gate.get("grant");
        let grant_ok = match grant {
            None => true,
            Some(v) if v.is_null() => true,
            Some(v) => v.as_str().map(|s| GRANTS.contains(&s)).unwrap_or(false),
        };
        if !grant_ok {
            issues.push(format!(
                "gate {gate_id} declares an unknown grant: {}",
                grant.map(|v| v.to_string()).unwrap_or_default()
            ));
        }
        let obligations = gate.get("obligations").and_then(|v| v.as_array());
        let obligations = match obligations {
            Some(o) if !o.is_empty() => o,
            _ => {
                issues.push(format!("gate {gate_id} declares no obligations"));
                continue;
            }
        };
        for obligation in obligations {
            let ob_id = obligation.get("id").and_then(|v| v.as_str());
            let requirement = obligation.get("requirement").and_then(|v| v.as_str());
            let (ob_id, _req) = match (ob_id, requirement) {
                (Some(i), Some(r)) => (i, r),
                _ => {
                    issues.push(format!("gate {gate_id} has an obligation missing id or requirement"));
                    continue;
                }
            };
            let implemented = obligation.get("implemented").and_then(|v| v.as_bool());
            if implemented == Some(false) {
                let has_gap = obligation
                    .get("gap")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false);
                if !has_gap {
                    issues.push(format!("obligation {ob_id} is unimplemented but names no gap"));
                }
                if obligation
                    .get("evidence")
                    .map(|v| !v.is_null())
                    .unwrap_or(false)
                {
                    issues.push(format!("obligation {ob_id} is unimplemented but names evidence"));
                }
                if !seen_obligations.insert(ob_id.to_string()) {
                    issues.push(format!("duplicate obligation id: {ob_id}"));
                }
                continue;
            }
            let evidence = obligation.get("evidence");
            let evidence_str = match evidence.and_then(|v| v.as_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => {
                    issues.push(format!(
                        "gate {gate_id} obligation {ob_id} names no evidence and is not marked unimplemented"
                    ));
                    continue;
                }
            };
            if !seen_obligations.insert(ob_id.to_string()) {
                issues.push(format!("duplicate obligation id: {ob_id}"));
            }
            let is_script = if let Some(rest) = evidence_str.strip_prefix("pnpm ") {
                has_script(rest.trim())
            } else {
                has_script(&evidence_str)
            };
            let is_file = evidence_str.contains('/') && root.join(&evidence_str).exists();
            let is_artifact =
                artifact_re.is_match(&evidence_str) || evidence_str.ends_with("stage-summary");
            if !is_script && !is_file && !is_artifact {
                issues.push(format!(
                    "obligation {ob_id} names an evidence producer that does not exist: {evidence_str}"
                ));
            }
        }
    }

    for grant in GRANTS {
        let owners = gates
            .iter()
            .filter(|g| g.get("grant").and_then(|v| v.as_str()) == Some(*grant))
            .count();
        if owners != 1 {
            issues.push(format!("grant {grant} must be owned by exactly one gate, found {owners}"));
        }
    }

    Report { ok: issues.is_empty(), issues }
}

pub fn run(root: &Path) -> bool {
    let report = check(root);
    if report.ok {
        println!("release obligations: consistent");
    } else {
        for issue in &report.issues {
            eprintln!("{issue}");
        }
    }
    report.ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "legion-obligations-{label}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(dir.join("release")).unwrap();
        dir
    }

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    // Port of "the shipped release obligations manifest is consistent".
    #[test]
    fn shipped_manifest_is_consistent() {
        let root = repo_root();
        let report = check(&root);
        assert!(report.ok, "issues: {:?}", report.issues);
    }

    fn repo_root() -> std::path::PathBuf {
        let mut dir = std::env::current_dir().unwrap();
        loop {
            if dir.join("package.json").is_file() && dir.join("engine").is_dir() {
                return dir;
            }
            if !dir.pop() {
                panic!("could not locate repository root above cwd");
            }
        }
    }

    // Port of "an obligation naming a nonexistent producer is rejected".
    #[test]
    fn nonexistent_evidence_producer_is_rejected() {
        let root = temp_dir("missing-producer");
        write(&root, "package.json", r#"{"scripts":{}}"#);
        write(
            &root,
            "release/obligations.json",
            r#"{
              "schemaVersion": 1, "kind": "legion-release-obligations", "product": "legion",
              "gates": [
                { "id": "0A", "name": "static", "grant": null, "obligations": [{ "id": "a", "requirement": "r", "evidence": "release:does-not-exist" }] },
                { "id": "1", "name": "candidate", "grant": "BUILD_AUTHORIZED", "obligations": [{ "id": "b", "requirement": "r", "evidence": "candidate stage-summary" }] },
                { "id": "3", "name": "sign", "grant": "SIGNING_AUTHORIZED", "obligations": [{ "id": "c", "requirement": "r", "evidence": "candidate stage-summary" }] },
                { "id": "6", "name": "auth", "grant": "RELEASE_AUTHORIZED", "obligations": [{ "id": "d", "requirement": "r", "evidence": "candidate stage-summary" }] }
              ]
            }"#,
        );
        let report = check(&root);
        assert!(!report.ok);
        assert!(
            report.issues.iter().any(|i| i.contains("does not exist")),
            "{}",
            report.issues.join("; ")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // Port of "an unimplemented obligation must name its gap".
    #[test]
    fn unimplemented_obligation_must_name_gap() {
        let root = temp_dir("gap");
        write(&root, "package.json", r#"{"scripts":{}}"#);
        write(
            &root,
            "release/obligations.json",
            r#"{
              "schemaVersion": 1, "kind": "legion-release-obligations", "product": "legion",
              "gates": [
                { "id": "0A", "name": "static", "grant": null, "obligations": [{ "id": "a", "requirement": "r", "evidence": null, "implemented": false }] },
                { "id": "1", "name": "candidate", "grant": "BUILD_AUTHORIZED", "obligations": [{ "id": "b", "requirement": "r", "evidence": "candidate stage-summary" }] },
                { "id": "3", "name": "sign", "grant": "SIGNING_AUTHORIZED", "obligations": [{ "id": "c", "requirement": "r", "evidence": "candidate stage-summary" }] },
                { "id": "6", "name": "auth", "grant": "RELEASE_AUTHORIZED", "obligations": [{ "id": "d", "requirement": "r", "evidence": "candidate stage-summary" }] }
              ]
            }"#,
        );
        let report = check(&root);
        assert!(!report.ok);
        assert!(
            report.issues.iter().any(|i| i.contains("names no gap")),
            "{}",
            report.issues.join("; ")
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
