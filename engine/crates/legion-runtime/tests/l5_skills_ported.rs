//! Integration tests for the ported `l5_skills` module (production entry points),
//! mirroring key cases from `src/lib/skills/{uri,skill-frontmatter,contracts,profile}.mjs`.

use legion_runtime::l5_skills::{
    parse_skill_frontmatter, parse_skill_uri, project_skill_text, skill_uri, validate_skill_bundle,
};
use serde_json::json;

#[test]
fn uri_round_trip_through_production_entry_point() {
    let built = skill_uri("qa", "references/notes.md");
    let parsed = parse_skill_uri(&built).unwrap();
    assert_eq!(parsed.bundle, "qa");
    assert_eq!(parsed.path, "references/notes.md");
}

#[test]
fn frontmatter_entry_point_rejects_invalid_kind() {
    let text = "---\nname: qa\ndescription: d\nkind: bogus\ndiscoverability: public\noperations: []\neffects: []\nhostRequirements: []\n---\n";
    let err = parse_skill_frontmatter(text, "SKILL.md").unwrap_err();
    assert!(err.contains("invalid kind"));
}

#[test]
fn contracts_entry_point_rejects_audit_profile_publish_grant() {
    let bundle = json!({
        "schemaVersion": 1,
        "id": "qa",
        "version": "1.0.0",
        "entry": "SKILL.md",
        "provenance": {"author": "legion"},
        "licenseState": "public-domain",
        "rightsReceipt": {"kind": "public-domain"},
        "rootUri": "legion-skill://qa/",
        "profiles": {
            "audit": {"mutation": false, "publish": true},
            "authoring": {"mutation": true, "publish": true},
        },
        "files": [
            {"path": "SKILL.md", "uri": "legion-skill://qa/SKILL.md", "digest": format!("sha256:{}", "a".repeat(64))},
        ],
    });
    assert!(validate_skill_bundle(&bundle).is_err());
}

#[test]
fn profile_entry_point_strips_publish_automation_line_under_audit() {
    let text = "This step will publish the release automatically.\nKeep this line.\n";
    let projected = project_skill_text(text, "qa", "SKILL.md", "audit");
    assert!(!projected.contains("publish the release automatically"));
    assert!(projected.contains("Keep this line."));
}

#[test]
fn profile_entry_point_preserves_publish_automation_line_under_authoring() {
    let text = "This step will publish the release automatically.\n";
    let projected = project_skill_text(text, "qa", "SKILL.md", "authoring");
    assert!(projected.contains("publish the release automatically"));
}
