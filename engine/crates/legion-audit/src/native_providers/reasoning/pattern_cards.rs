//! Bounded semantic pattern cards selected by the existing audit lenses.
//!
//! Cards sharpen correctness, schema, data-safety, security, and performance
//! review. They do not add lenses or replace the runtime's existing provider
//! triggers. Each card requires a source trace, names a falsifier, and keeps
//! an unresolved trace explicitly unknown.

use serde_json::{json, Value};

/// Only source-language restrictions established by a card's existing prose.
/// Framework and trigger fit still require review; they cannot exclude a card.
#[derive(Clone, Copy, Debug)]
pub enum LanguageApplicability {
    JavaScriptOrTypeScript,
}

#[derive(Clone, Copy, Debug)]
pub struct PatternCard {
    pub version: &'static str,
    pub id: &'static str,
    pub owner_lens: &'static str,
    pub applicability: &'static str,
    pub language_applicability: Option<LanguageApplicability>,
    pub trigger_evidence: &'static str,
    pub required_source_trace: &'static str,
    pub falsifier: &'static str,
    pub no_evidence: &'static str,
    pub positive_case: &'static str,
    pub negative_case: &'static str,
}

impl PatternCard {
    fn to_packet_value(self) -> Value {
        let mut value = json!({
            "version": self.version,
            "id": self.id,
            "ownerLens": self.owner_lens,
            "applicability": self.applicability,
            "triggerEvidence": self.trigger_evidence,
            "requiredSourceTrace": self.required_source_trace,
            "falsifier": self.falsifier,
            "noEvidence": self.no_evidence,
            "pairedCases": {
                "positive": self.positive_case,
                "negative": self.negative_case,
            },
        });
        if let Some(LanguageApplicability::JavaScriptOrTypeScript) = self.language_applicability {
            value["languageApplicability"] = json!({"languages": ["javascript", "typescript"]});
        }
        value
    }
}

/// Versioned patterns attached only to their existing owning lens.
/// Applicability describes language/framework fit; deterministic provider
/// trigger evaluation remains owned by the frozen plan.
pub const PATTERN_CARDS: &[PatternCard] = &[
    PatternCard {
        version: "1",
        id: "return-key-consumer-migration",
        owner_lens: "correctness",
        applicability: "Serialized key/column changes: object/RPC/endpoint/SQL view/function/table; any producer/consumer language.",
        language_applicability: None,
        trigger_evidence: "Diff removes/renames emitted field/column.",
        required_source_trace: "Compare old/new shape; trace old-key readers via repo callers/RPCs/routes; log every reader & untraced boundary.",
        falsifier: "All consumers migrated/removed together; new payload; or never serialized.",
        no_evidence: "Untraced caller migration -> unknown contract impact; trace each before claiming breakage.",
        positive_case: "An endpoint renames `accountId` to `ownerId` while an in-repository client still reads `accountId`.",
        negative_case: "The same change updates every traced reader, or removes all consumers along with the field.",
    },
    PatternCard {
        version: "1",
        id: "interactive-state-derived-output",
        owner_lens: "correctness",
        applicability: "React/Vue/Svelte/equivalent interactive state/store UI.",
        language_applicability: None,
        trigger_evidence: "User action changes/adds state; nearby rendered/computed output seems linked.",
        required_source_trace: "Trace handler state write -> every dependent rendered value/filter/summary/alert/submit payload.",
        falsifier: "Intentionally control-independent output; or documented seed/default correctly merges live state.",
        no_evidence: "Unclear state/output link -> unknown; names alone don't establish intent.",
        positive_case: "A selected-category control updates state but the alert list continues reading a separate static default list.",
        negative_case: "A star toggle changes only its own presentation and no other output is meant to track it.",
    },
    PatternCard {
        version: "1",
        id: "upsert-replay-workflow-state",
        owner_lens: "data-safety",
        applicability: "Database upsert/on-conflict/merge writes in application code or SQL, across supported repository languages.",
        language_applicability: None,
        trigger_evidence: "A replayable insert/upsert supplies a literal to a workflow-bearing field such as status, stage, state, phase, tier, or role.",
        required_source_trace: "Trace the conflict/update column list and guards, then inspect relevant helper, trigger, or generated-column behavior before concluding the state is overwritten.",
        falsifier: "Conflict handling ignores duplicates, omits the state column, or constrains updates to an explicitly safe current state.",
        no_evidence: "If a wrapper, trigger, or database policy may provide a guard and its behavior is unavailable, report unknown.",
        positive_case: "A webhook replay updates a matching order and writes `status = 'pending'` after the order advanced.",
        negative_case: "`DO UPDATE` changes only profile fields and omits the workflow status column.",
    },
    PatternCard {
        version: "1",
        id: "migration-later-object-order",
        owner_lens: "data-safety",
        applicability: "Timestamp-ordered SQL migrations, including migrations that include or execute external SQL files.",
        language_applicability: None,
        trigger_evidence: "A migration references a table, column, type, function, policy, or view whose declaration is not visible in the same migration.",
        required_source_trace: "Resolve each referenced object to its creation/alteration source and compare migration timestamps, including transitive includes and documented baseline objects.",
        falsifier: "The object exists in an earlier or same-order migration, a guaranteed baseline, or a known built-in/extension.",
        no_evidence: "If object origin or migration order cannot be established, report fresh-apply behavior as unknown.",
        positive_case: "Migration 020 adds a policy that uses a column first added in migration 030.",
        negative_case: "The referenced column is created in migration 010 or in a guaranteed baseline applied first.",
    },
    PatternCard {
        version: "1",
        id: "postgres-definer-searchpath-and-public-execute",
        owner_lens: "security",
        applicability: "PostgreSQL functions, including Supabase migrations and RPCs.",
        language_applicability: None,
        trigger_evidence: "A created or altered function uses SECURITY DEFINER, especially when search_path or EXECUTE grants change or are inherited from defaults.",
        required_source_trace: "Read the complete function body and fixed SET search_path; trace effective EXECUTE grants/revokes, untrusted caller reachability, and documented/API-policy intended roles.",
        falsifier: "Name resolution is pinned away from caller-controlled schemas and effective access matches an evidenced intended audience; PUBLIC execution alone is not a defect without a conflicting access policy.",
        no_evidence: "If function body, search-path resolution, effective ACL, caller reachability, or intended audience cannot be established, report that property as unknown.",
        positive_case: "An untrusted role can call a definer function with caller-influenced name resolution, or PUBLIC retains EXECUTE contrary to an evidenced private access policy.",
        negative_case: "A definer function pins a safe search_path and verified grants match its documented caller audience.",
    },
    PatternCard {
        version: "1",
        id: "supabase-single-missing-row-response",
        owner_lens: "correctness",
        applicability: "Supabase/PostgREST JS/TS `.single()` by request-derived ID.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        trigger_evidence: "Possible zero rows; request/unproven-lookup key.",
        required_source_trace: "Trace ID origin, cardinality/guards, `{data,error}` handling & response mapping; separate returned PostgREST errors from throws.",
        falsifier: "Proven row before query; intentional `.maybeSingle()` absence mapping; or PGRST116 -> expected not-found.",
        no_evidence: "Untraced cardinality/prior existence/response mapping -> unknown; returned error isn't thrown.",
        positive_case: "An edge handler calls `.single()` by request ID and returns 500 for a returned PGRST116 result.",
        negative_case: "The handler uses `.maybeSingle()` and maps `data === null` to 404, or handles PGRST116 in its returned error path.",
    },
    PatternCard {
        version: "1",
        id: "qualified-function-create-unqualified-comment",
        owner_lens: "data-safety",
        applicability: "PostgreSQL/Supabase SQL migrations containing CREATE FUNCTION and COMMENT ON FUNCTION.",
        language_applicability: None,
        trigger_evidence: "A function is created schema-qualified and later commented by name in the same migration or included SQL.",
        required_source_trace: "Compare the exact schema and argument signature in CREATE and COMMENT statements, then inspect migration-level SET search_path applying to COMMENT.",
        falsifier: "COMMENT is schema-qualified consistently, CREATE is intentionally unqualified under the same convention, or statement scope pins the matching schema.",
        no_evidence: "If included definitions or session search_path are unavailable, report resolution as unknown; a function body's SET search_path does not establish migration-session scope.",
        positive_case: "`CREATE FUNCTION public.refresh()` is followed by `COMMENT ON FUNCTION refresh()` with no migration-level search_path guarantee.",
        negative_case: "`COMMENT ON FUNCTION public.refresh()` matches the qualified CREATE.",
    },
    PatternCard {
        version: "1",
        id: "environment-read-before-config-loader",
        owner_lens: "correctness",
        applicability: "Node.js JS/TS: process.env & dotenv/process.loadEnvFile/manual setup.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        trigger_evidence: "Export/config/client reads process.env at module evaluation.",
        required_source_trace: "Trace entry loader/consumer import/evaluation order & export read/use timing.",
        falsifier: "Lazy read after load; dynamic import after config; or documented build-time constant.",
        no_evidence: "Top-level env read alone is not a bug; untraced initialization order -> unknown.",
        positive_case: "An entry imports a client module before calling loadEnvFile, while that module captures process.env.API_URL at top level.",
        negative_case: "The entry loads environment first and dynamically imports the client, or the client reads process.env inside a later-called function.",
    },
    PatternCard {
        version: "1",
        id: "react-render-state-and-eager-initializer-effects",
        owner_lens: "correctness",
        applicability: "React function components in JSX/TSX.",
        language_applicability: Some(LanguageApplicability::JavaScriptOrTypeScript),
        trigger_evidence: "Render-scope setter or nontrivial eager useState argument.",
        required_source_trace: "Trace setter scope/guard; per-render useState(expr) cost/effects; lazy initializer purity/behavior.",
        falsifier: "Event/effect/callback setter or proven guarded derive-state; cheap/pure initializer or lazy expensive work.",
        no_evidence: "Unclear scope/guard/cost/effect -> unknown; setter/useState alone is not a defect.",
        positive_case: "Render unconditionally calls setOpen, or `useState(parseLargePayload())` repeats parsing on every render.",
        negative_case: "A conditional setter compares incoming props with prior state, or `useState(() => parseLargePayload())` lazily computes a pure value.",
    },
    PatternCard {
        version: "1",
        id: "promise-all-independent-partial-effects",
        owner_lens: "performance",
        applicability: "JavaScript/TypeScript Promise.all over independent writes, sends, publishes, or other side effects.",
        language_applicability: None,
        trigger_evidence: "Promise.all groups independent side effects whose partial completion affects retry or recovery.",
        required_source_trace: "Identify each operation's side effect and caller's failure handling, then trace whether per-item completion/results are persisted or inspected.",
        falsifier: "All entries are reads, use Promise.allSettled, or individually convert rejection into a per-item result before aggregation.",
        no_evidence: "If operations are not established as independent side effects or recovery semantics are unavailable, report partial completion as unknown.",
        positive_case: "Promise.all sends three webhooks; one rejection hides which other deliveries succeeded before retry.",
        negative_case: "Promise.all gathers independent reads, or Promise.allSettled records every write outcome.",
    },
];

/// Returns only cards owned by the lens already selected for this seat.
pub fn cards_for_lens(lens: &str) -> impl Iterator<Item = &'static PatternCard> + '_ {
    PATTERN_CARDS
        .iter()
        .filter(move |card| card.owner_lens == lens)
}

/// Serializes selected cards for the existing reasoning packet.
pub fn packet_cards_for_lens(lens: &str) -> Vec<Value> {
    cards_for_lens(lens)
        .copied()
        .map(PatternCard::to_packet_value)
        .collect()
}

/// Bind cards after source selection/partitioning, never from repository-wide
/// language guesses. Unknown language, framework, or trigger fit retains work.
pub fn bind_packet_cards_to_paths(lens_plan: &mut Value, selected_paths: &[String]) {
    let Some(lens) = lens_plan.get("lens").and_then(Value::as_str) else {
        return;
    };
    let mut source_paths = selected_paths
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    source_paths.sort_unstable();
    source_paths.dedup();
    let language_fit = javascript_typescript_fit(&source_paths);
    let mut retained = Vec::new();
    let mut accounting = Vec::new();
    for card in cards_for_lens(lens) {
        let (state, reason) = match card.language_applicability {
            None => ("retained", "no-language-restriction"),
            Some(LanguageApplicability::JavaScriptOrTypeScript) => language_fit,
        };
        if state != "excluded" {
            retained.push(card.to_packet_value());
        }
        accounting.push(json!({"id": card.id, "state": state, "reason": reason}));
    }
    lens_plan["patternCards"] = json!(retained);
    // One shared exact path identity binds every candidate's decision without
    // repeating paths or card bodies in each accounting row.
    lens_plan["patternCardApplicability"] = json!({
        "sourcePaths": source_paths,
        "cards": accounting,
    });
}

fn javascript_typescript_fit(paths: &[&str]) -> (&'static str, &'static str) {
    if paths.is_empty() {
        return ("unknown", "selected-source-paths-empty");
    }
    let mut unknown = false;
    for path in paths {
        let lower = path.to_ascii_lowercase();
        if [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]
            .iter()
            .any(|extension| lower.ends_with(*extension))
        {
            return ("retained", "selected-source-includes-javascript-typescript");
        }
        if ![".rs", ".swift", ".py"]
            .iter()
            .any(|extension| lower.ends_with(*extension))
        {
            unknown = true;
        }
    }
    if unknown {
        ("unknown", "selected-source-language-unknown")
    } else {
        (
            "excluded",
            "selected-source-languages-exclude-javascript-typescript",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn bound_cards(paths: &[&str]) -> Value {
        let mut packet = json!({"lens": "correctness"});
        bind_packet_cards_to_paths(
            &mut packet,
            &paths
                .iter()
                .map(|path| (*path).to_owned())
                .collect::<Vec<_>>(),
        );
        packet
    }

    fn card_ids(packet: &Value) -> BTreeSet<&str> {
        packet["patternCards"]
            .as_array()
            .unwrap()
            .iter()
            .map(|card| card["id"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn recognized_non_javascript_source_excludes_exactly_three_correctness_cards() {
        let expected = BTreeSet::from([
            "return-key-consumer-migration",
            "interactive-state-derived-output",
        ]);
        for paths in [
            vec!["src/lib.rs"],
            vec!["src/react_supabase_process.env.rs"],
            vec!["src/view.swift"],
            vec!["src/app.py"],
            vec!["src/lib.rs", "src/view.swift", "src/app.py"],
        ] {
            let bound = bound_cards(&paths);
            assert_eq!(card_ids(&bound), expected);
            let accounting = bound["patternCardApplicability"]["cards"]
                .as_array()
                .unwrap();
            assert_eq!(accounting.len(), 5);
            assert_eq!(
                accounting
                    .iter()
                    .filter(|row| row["state"] == "excluded")
                    .count(),
                3
            );
            for row in accounting.iter().filter(|row| row["state"] == "excluded") {
                assert_eq!(
                    row["reason"],
                    "selected-source-languages-exclude-javascript-typescript"
                );
            }
        }
    }

    #[test]
    fn javascript_typescript_or_unknown_fit_never_removes_cards() {
        let expected = cards_for_lens("correctness")
            .map(|card| card.id)
            .collect::<BTreeSet<_>>();
        for extension in ["js", "jsx", "mjs", "cjs", "ts", "tsx", "TSX"] {
            let path = format!("src/plain.{extension}");
            let bound = bound_cards(&[&path]);
            assert_eq!(card_ids(&bound), expected);
            // Plain JS/TS establishes language, never React or trigger fit.
            assert!(bound["patternCardApplicability"]["cards"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["state"] == "retained"));
        }
        for paths in [
            vec![],
            vec!["src/unknown.sql"],
            vec!["src/extensionless"],
            vec!["src/lib.rs", "src/unknown.sql"],
            vec!["src/lib.rs", "src/view.tsx"],
            vec!["src/lib.rs", "src/view.tsx", "src/unknown.sql"],
        ] {
            let bound = bound_cards(&paths);
            assert_eq!(card_ids(&bound), expected);
            assert!(!bound["patternCardApplicability"]["cards"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["state"] == "excluded"));
        }
        for paths in [vec![], vec!["src/lib.rs", "src/unknown.sql"]] {
            let bound = bound_cards(&paths);
            assert_eq!(
                bound["patternCardApplicability"]["cards"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|row| row["state"] == "unknown")
                    .count(),
                3
            );
        }
    }

    #[test]
    fn accounting_has_one_state_per_candidate_and_stable_source_identity() {
        let bound = bound_cards(&["src/z.rs", "src/a.py", "src/z.rs"]);
        let reordered = bound_cards(&["src/a.py", "src/z.rs"]);
        assert_eq!(bound, reordered);
        assert_eq!(
            bound["patternCardApplicability"]["sourcePaths"],
            json!(["src/a.py", "src/z.rs"])
        );
        let rows = bound["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap();
        let accounted = rows
            .iter()
            .map(|row| {
                assert!(matches!(
                    row["state"].as_str(),
                    Some("retained" | "excluded" | "unknown")
                ));
                assert!(row["reason"].is_string());
                assert_eq!(row.as_object().unwrap().len(), 3);
                row["id"].as_str().unwrap()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(accounted.len(), rows.len());
        assert_eq!(
            accounted,
            cards_for_lens("correctness")
                .map(|card| card.id)
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn metadata_only_restricts_three_explicit_correctness_cards() {
        let restricted = PATTERN_CARDS
            .iter()
            .filter(|card| card.language_applicability.is_some())
            .map(|card| card.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            restricted,
            BTreeSet::from([
                "supabase-single-missing-row-response",
                "environment-read-before-config-loader",
                "react-render-state-and-eager-initializer-effects",
            ])
        );
        for lens in ["data-safety", "security", "performance"] {
            let mut bound = json!({"lens": lens});
            bind_packet_cards_to_paths(&mut bound, &["src/lib.rs".into()]);
            assert_eq!(bound["patternCards"], json!(packet_cards_for_lens(lens)));
        }
    }

    #[test]
    fn every_card_has_required_versioned_trace_and_paired_cases() {
        let mut ids = BTreeSet::new();
        for card in PATTERN_CARDS {
            assert_eq!(card.version, "1");
            assert!(ids.insert(card.id), "duplicate card id {}", card.id);
            assert!(!card.id.is_empty());
            assert!(!card.owner_lens.is_empty());
            assert!(!card.applicability.is_empty());
            assert!(!card.trigger_evidence.is_empty());
            assert!(!card.required_source_trace.is_empty());
            assert!(!card.falsifier.is_empty());
            assert!(!card.no_evidence.is_empty());
            assert!(!card.positive_case.is_empty());
            assert!(!card.negative_case.is_empty());
        }
    }

    #[test]
    fn routing_returns_only_cards_owned_by_existing_lenses() {
        for card in PATTERN_CARDS {
            assert!(cards_for_lens(card.owner_lens).any(|selected| selected.id == card.id));
        }
        assert!(cards_for_lens("architecture").next().is_none());
        assert!(cards_for_lens("unknown").next().is_none());
        assert_eq!(cards_for_lens("security").count(), 1);
        assert_eq!(cards_for_lens("performance").count(), 1);
    }

    #[test]
    fn packet_cards_preserve_required_fields_and_unknown_policy() {
        let cards = packet_cards_for_lens("correctness");
        assert!(!cards.is_empty());
        for card in cards {
            for field in [
                "version",
                "id",
                "ownerLens",
                "applicability",
                "triggerEvidence",
                "requiredSourceTrace",
                "falsifier",
                "noEvidence",
            ] {
                assert!(card.get(field).is_some(), "missing {field}");
            }
            assert!(card["pairedCases"]["positive"].is_string());
            assert!(card["pairedCases"]["negative"].is_string());
        }
    }
}
