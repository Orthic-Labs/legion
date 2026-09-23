//! Faithful port of `src/lib/host/arcane/stop-disposition.mjs`.
//!
//! "Termination is independent from certification. Only a verified pending
//! operation may request completion." — carried forward from the JS
//! comment: `stop_outcome` always allows termination; only the
//! `certification` field distinguishes an authenticated completion claim
//! from every other stop.

/// JS `STOP_DISPOSITIONS` (a frozen array there; a fixed slice here — the
/// membership and order are the load-bearing part, not mutability).
pub const STOP_DISPOSITIONS: [&str; 5] = ["completion", "question", "pause", "archive", "other"];

/// Mirrors the JS `classifyStopDisposition({ authenticatedClaim, intent })`
/// destructured-argument-with-defaults shape: `authenticated_claim` defaults
/// to `false` and `intent` defaults to `"UNKNOWN"` at call sites that don't
/// have an opinion.
#[derive(Debug, Clone)]
pub struct StopDispositionInput<'a> {
    pub authenticated_claim: bool,
    pub intent: &'a str,
}

impl Default for StopDispositionInput<'_> {
    fn default() -> Self {
        Self {
            authenticated_claim: false,
            intent: "UNKNOWN",
        }
    }
}

/// Port of `classifyStopDisposition`. `intent` values that mean "the turn
/// is not actually finishing" are classified `question` regardless of
/// `authenticatedClaim` (an authenticated claim cannot override an
/// in-progress intent); otherwise an authenticated claim yields
/// `completion`, and anything else falls through to `other`.
pub fn classify_stop_disposition(input: &StopDispositionInput<'_>) -> &'static str {
    if matches!(
        input.intent,
        "QUESTION" | "PLAN" | "PAUSE" | "REVOKE" | "SCOPE_NARROW"
    ) {
        return "question";
    }
    if input.authenticated_claim {
        return "completion";
    }
    "other"
}

/// Port of `stopOutcome`. Termination is always allowed; certification is
/// `genuine` only for a `completion` disposition, `not_claimed` otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopOutcome {
    pub disposition: &'static str,
    pub termination_allowed: bool,
    pub certification: &'static str,
}

pub fn stop_outcome(input: &StopDispositionInput<'_>) -> StopOutcome {
    let disposition = classify_stop_disposition(input);
    StopOutcome {
        disposition,
        termination_allowed: true,
        certification: if disposition == "completion" {
            "genuine"
        } else {
            "not_claimed"
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_dispositions_matches_js_order_and_membership() {
        assert_eq!(
            STOP_DISPOSITIONS,
            ["completion", "question", "pause", "archive", "other"]
        );
    }

    #[test]
    fn default_input_is_unknown_intent_unauthenticated() {
        let input = StopDispositionInput::default();
        assert_eq!(input.intent, "UNKNOWN");
        assert!(!input.authenticated_claim);
        assert_eq!(classify_stop_disposition(&input), "other");
    }

    // Mirrors the JS integration test's stop-disposition matrix: UNKNOWN,
    // QUESTION, PLAN, PAUSE with authenticatedClaim=false all terminate and
    // are never certified genuine.
    #[test]
    fn unauthenticated_intents_always_terminate_and_are_not_claimed() {
        for intent in ["UNKNOWN", "QUESTION", "PLAN", "PAUSE", "REVOKE", "SCOPE_NARROW"] {
            let outcome = stop_outcome(&StopDispositionInput {
                authenticated_claim: false,
                intent,
            });
            assert!(outcome.termination_allowed);
            assert_eq!(outcome.certification, "not_claimed");
        }
    }

    #[test]
    fn in_progress_intents_classify_question_even_when_claim_is_authenticated() {
        // An authenticated claim cannot override an in-progress intent: the
        // JS `if (...).includes(intent)) return 'question'` check runs
        // before the `authenticatedClaim` check.
        for intent in ["QUESTION", "PLAN", "PAUSE", "REVOKE", "SCOPE_NARROW"] {
            let disposition = classify_stop_disposition(&StopDispositionInput {
                authenticated_claim: true,
                intent,
            });
            assert_eq!(disposition, "question");
        }
    }

    #[test]
    fn authenticated_completion_is_genuine() {
        let outcome = stop_outcome(&StopDispositionInput {
            authenticated_claim: true,
            intent: "UNKNOWN",
        });
        assert_eq!(outcome.disposition, "completion");
        assert!(outcome.termination_allowed);
        assert_eq!(outcome.certification, "genuine");
    }

    #[test]
    fn unauthenticated_unknown_intent_is_other_not_claimed() {
        let outcome = stop_outcome(&StopDispositionInput {
            authenticated_claim: false,
            intent: "UNKNOWN",
        });
        assert_eq!(outcome.disposition, "other");
        assert!(outcome.termination_allowed);
        assert_eq!(outcome.certification, "not_claimed");
    }

    #[test]
    fn unrecognized_intent_falls_through_like_unknown() {
        // JS has no default branch beyond the includes() check and the
        // authenticatedClaim check, so any intent string not in the
        // in-progress set behaves exactly like "UNKNOWN".
        let outcome = stop_outcome(&StopDispositionInput {
            authenticated_claim: false,
            intent: "SOMETHING_ELSE",
        });
        assert_eq!(outcome.disposition, "other");
        assert_eq!(outcome.certification, "not_claimed");
    }
}
