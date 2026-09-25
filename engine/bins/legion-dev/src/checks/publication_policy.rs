// Port of `scripts/check-publication-policy.mjs`. Public channels require an
// explicit grant bound to current shipped surface (a policy digest of
// `package.json#files` + `MANIFEST.package.json#allowlistedTopLevel`).

use super::publication_surface;
use super::read_json;
use sha2::{Digest, Sha256};
use std::path::Path;

fn internal_channels() -> &'static [&'static str] {
    &["internal-pack", "local-test", "ci-test"]
}

pub fn publication_surface_digest(root: &Path) -> Result<String, String> {
    let pkg = read_json(&root.join("package.json"))?;
    let manifest = read_json(&root.join("MANIFEST.package.json"))?;
    let canonical = serde_json::json!({
        "files": pkg.get("files").cloned().unwrap_or(serde_json::Value::Null),
        "allowlistedTopLevel": manifest.get("allowlistedTopLevel").cloned().unwrap_or(serde_json::Value::Null),
    });
    let canonical_str = serde_json::to_string(&canonical).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(canonical_str.as_bytes());
    let digest = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(digest)))
}

pub struct Outcome {
    pub status: &'static str,
    pub exit_code: i32,
    pub message: String,
}

pub fn check_publication_channel(channel: Option<&str>, root: &Path) -> Outcome {
    let channel = match channel {
        Some(c) if !c.is_empty() => c,
        _ => {
            return Outcome {
                status: "error",
                exit_code: 4,
                message: "usage: check-publication-policy.mjs --channel <name>".to_string(),
            }
        }
    };
    if internal_channels().contains(&channel) {
        return Outcome {
            status: "pass",
            exit_code: 0,
            message: format!("internal channel allowed: {channel}"),
        };
    }
    let policy_path = root.join("release/publication-policy.json");
    if !policy_path.is_file() {
        return Outcome {
            status: "blocked",
            exit_code: 5,
            message: format!("publication blocked: {} is absent", policy_path.display()),
        };
    }
    let policy = match read_json(&policy_path) {
        Ok(v) => v,
        Err(_) => {
            return Outcome {
                status: "blocked",
                exit_code: 5,
                message: "publication blocked: invalid policy".to_string(),
            }
        }
    };
    let valid = policy.get("schemaVersion").and_then(|v| v.as_i64()) == Some(2)
        && policy.get("kind").and_then(|v| v.as_str()) == Some("legion-publication-policy");
    if !valid {
        return Outcome {
            status: "blocked",
            exit_code: 5,
            message: "publication blocked: invalid policy".to_string(),
        };
    }
    let grant = policy.get("channels").and_then(|c| c.get(channel));
    if let Some(grant) = grant {
        if grant.get("allowed").and_then(|v| v.as_bool()) == Some(false) {
            let evidence: Vec<String> = grant
                .get("requiredEvidence")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let reason = grant
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("no authorization");
            let evidence_str = evidence.join(", ");
            let message = if evidence_str.is_empty() {
                format!("publication blocked: channel {channel} is denied ({reason})")
            } else {
                format!(
                    "publication blocked: channel {channel} is denied ({reason}); required evidence: {evidence_str}"
                )
            };
            return Outcome { status: "blocked", exit_code: 5, message };
        }
    }
    let allowed = grant.and_then(|g| g.get("allowed")).and_then(|v| v.as_bool()) == Some(true);
    let approved_by = grant.and_then(|g| g.get("approvedBy")).and_then(|v| v.as_str());
    let approved_at = grant.and_then(|g| g.get("approvedAt")).and_then(|v| v.as_str());
    let policy_digest = grant.and_then(|g| g.get("policyDigest")).and_then(|v| v.as_str());
    if !allowed || approved_by.is_none() || approved_at.is_none() || policy_digest.is_none() {
        return Outcome {
            status: "blocked",
            exit_code: 5,
            message: format!("publication blocked: channel {channel} has no complete grant"),
        };
    }
    let observed = match publication_surface_digest(root) {
        Ok(d) => d,
        Err(e) => {
            return Outcome {
                status: "blocked",
                exit_code: 5,
                message: format!("publication blocked: {e}"),
            }
        }
    };
    if policy_digest != Some(observed.as_str()) {
        return Outcome {
            status: "blocked",
            exit_code: 5,
            message: format!(
                "publication blocked: channel {channel} policy digest drift (declared {}, current {observed})",
                policy_digest.unwrap_or_default()
            ),
        };
    }
    let surface = publication_surface::check(root);
    if !surface.ok {
        return Outcome {
            status: "blocked",
            exit_code: 5,
            message: format!("publication blocked: {}", surface.message),
        };
    }
    Outcome {
        status: "pass",
        exit_code: 0,
        message: format!("publication channel allowed: {channel}"),
    }
}

pub fn run(root: &Path, channel: Option<&str>) -> ! {
    let result = check_publication_channel(channel, root);
    if result.exit_code == 0 {
        println!("{}", result.message);
    } else {
        eprintln!("{}", result.message);
    }
    // JS uses distinct codes (4 = usage error, 5 = blocked, 0 = pass); exit
    // directly so the caller sees the same code, not just 0/1.
    std::process::exit(result.exit_code);
}
