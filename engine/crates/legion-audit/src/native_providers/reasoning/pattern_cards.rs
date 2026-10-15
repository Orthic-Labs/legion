//! Bounded semantic pattern cards selected by the existing audit lenses.
//!
//! Cards sharpen correctness, schema, data-safety, security, and performance
//! review. They do not add lenses or replace the runtime's existing provider
//! triggers. Each card requires a source trace, names a falsifier, and keeps
//! an unresolved trace explicitly unknown.

use serde_json::{json, Value};

#[derive(Clone, Copy, Debug)]
pub struct PatternCard {
    pub version: &'static str,
    pub id: &'static str,
    pub owner_lens: &'static str,
    pub applicability: &'static str,
    pub trigger_evidence: &'static str,
    pub required_source_trace: &'static str,
    pub falsifier: &'static str,
    pub no_evidence: &'static str,
    pub positive_case: &'static str,
    pub negative_case: &'static str,
}

impl PatternCard {
    fn to_packet_value(self) -> Value {
        json!({
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
        })
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
        applicability: "Serialized object, RPC, endpoint, SQL view/function, or table shape with a changed return key/column; language-agnostic at the producer/consumer boundary.",
        trigger_evidence: "A diff removes or renames a previously emitted field or return column.",
        required_source_trace: "Compare old/new output shape, then trace old-key readers through repository callers, RPC names, or endpoint routes; record every confirmed reader and any untraced boundary.",
        falsifier: "All consumers are removed or migrated in the same change, the payload is new, or the field was never serialized.",
        no_evidence: "If consumer migration cannot be confirmed, report contract impact as unknown; never claim a caller is broken without tracing it.",
        positive_case: "An endpoint renames `accountId` to `ownerId` while an in-repository client still reads `accountId`.",
        negative_case: "The same change updates every traced reader, or removes all consumers along with the field.",
    },
    PatternCard {
        version: "1",
        id: "interactive-state-derived-output",
        owner_lens: "correctness",
        applicability: "Interactive UI using React, Vue, Svelte, or an equivalent state/store model.",
        trigger_evidence: "A user action adds or changes state and a nearby rendered/computed output appears to describe that state.",
        required_source_trace: "Trace the event handler's state write to every semantically dependent rendered value, filter, summary, alert, or submit payload.",
        falsifier: "The output intentionally does not depend on the control, or a documented seed/default is correctly merged with live state.",
        no_evidence: "If the output's relationship to the state is unclear, leave the relationship unknown instead of inferring intent from similar names.",
        positive_case: "A selected-category control updates state but the alert list continues reading a separate static default list.",
        negative_case: "A star toggle changes only its own presentation and no other output is meant to track it.",
    },
    PatternCard {
        version: "1",
        id: "upsert-replay-workflow-state",
        owner_lens: "data-safety",
        applicability: "Database upsert/on-conflict/merge writes in application code or SQL, across supported repository languages.",
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
        applicability: "Supabase/PostgREST JavaScript or TypeScript queries using `.single()` for a request-derived identifier.",
        trigger_evidence: "A `.single()` query may match zero rows and its key comes from request input or another unproven lookup.",
        required_source_trace: "Trace identifier origin, query cardinality/guards, returned `{data,error}` handling, and the outward response mapping; distinguish returned PostgREST errors from thrown exceptions.",
        falsifier: "The row is proven to exist before this query, `.maybeSingle()` maps absence intentionally, or PGRST116 is explicitly mapped to the expected not-found result.",
        no_evidence: "If cardinality, prior existence proof, or error-to-response mapping cannot be traced, report unknown; do not describe a returned result error as a thrown exception.",
        positive_case: "An edge handler calls `.single()` by request ID and returns 500 for a returned PGRST116 result.",
        negative_case: "The handler uses `.maybeSingle()` and maps `data === null` to 404, or handles PGRST116 in its returned error path.",
    },
    PatternCard {
        version: "1",
        id: "qualified-function-create-unqualified-comment",
        owner_lens: "data-safety",
        applicability: "PostgreSQL/Supabase SQL migrations containing CREATE FUNCTION and COMMENT ON FUNCTION.",
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
        applicability: "Node.js JavaScript/TypeScript modules using process.env and dotenv/process.loadEnvFile/manual setup.",
        trigger_evidence: "An exported/config/client value reads process.env during module evaluation.",
        required_source_trace: "Trace import/evaluation order from the entry point through the loader and consumer; establish when the exported value is read and used.",
        falsifier: "The value is read lazily after loading, the entry dynamically imports after configuration, or the value is a documented build-time constant.",
        no_evidence: "A top-level environment read alone is not a bug; without an ordering trace, report initialization ordering as unknown.",
        positive_case: "An entry imports a client module before calling loadEnvFile, while that module captures process.env.API_URL at top level.",
        negative_case: "The entry loads environment first and dynamically imports the client, or the client reads process.env inside a later-called function.",
    },
    PatternCard {
        version: "1",
        id: "react-render-state-and-eager-initializer-effects",
        owner_lens: "correctness",
        applicability: "React function components in JSX/TSX.",
        trigger_evidence: "A state setter occurs in render scope or useState receives a nontrivial eager expression.",
        required_source_trace: "Trace setter call scope and its guard; for useState(expr), establish per-render evaluation and whether expression is expensive or effectful. Check lazy initializer purity and behavior.",
        falsifier: "The setter is in an event/effect/callback or a provably guarded derive-state path; initializer is cheap/pure, or expensive work uses a lazy initializer.",
        no_evidence: "If call scope, guard, cost, or side effect is unclear, report unknown; do not flag merely because a setter or useState appears in the component.",
        positive_case: "Render unconditionally calls setOpen, or `useState(parseLargePayload())` repeats parsing on every render.",
        negative_case: "A conditional setter compares incoming props with prior state, or `useState(() => parseLargePayload())` lazily computes a pure value.",
    },
    PatternCard {
        version: "1",
        id: "promise-all-independent-partial-effects",
        owner_lens: "performance",
        applicability: "JavaScript/TypeScript Promise.all over independent writes, sends, publishes, or other side effects.",
        trigger_evidence: "Promise.all groups independent side effects whose partial completion affects retry or recovery.",
        required_source_trace: "Identify each operation's side effect and caller's failure handling, then trace whether per-item completion/results are persisted or inspected.",
        falsifier: "All entries are reads, use Promise.allSettled, or individually convert rejection into a per-item result before aggregation.",
        no_evidence: "If operations are not established as independent side effects or recovery semantics are unavailable, report partial completion as unknown.",
        positive_case: "Promise.all sends three webhooks; one rejection hides which other deliveries succeeded before retry.",
        negative_case: "Promise.all gathers independent reads, or Promise.allSettled records every write outcome.",
    },
];

/// Returns only cards owned by the lens already selected for this seat.
pub fn cards_for_lens(lens: &str) -> impl Iterator<Item = &'static PatternCard> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
