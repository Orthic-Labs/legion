//! Faithful port of `src/lib/verification/arcane/ingest.mjs` (`HostIngestor`).
//!
//! S04 — trusted host activity flows into Arcane without model re-entry and
//! without confusing success with proof. `authority='host'` is necessary but
//! never sufficient on its own: the caller must additionally present a
//! verified auth envelope or an explicit connection-trust assertion. A
//! model-asserted authority is refused before either path is considered.
//!
//! Scope gap vs. JS (see the wf072 report): this chunk owns
//! `verification/arcane/**` only. `ingest.mjs` imports four modules this
//! chunk does not own — `host/arcane/host-event.mjs` (`validateHostEvent`,
//! `classifyObservation`, `HOST_EVENT_BOUND_FIELDS`),
//! `guard/compat/audit/receipt-auth.mjs` (`verifyRecord`,
//! `authenticationBlock`, `connectionTrustBlock`; wf006 already ports the
//! sibling `receipt-auth.mjs` primitives, but wf006 is not wired into
//! `wf_port` yet, so wf072 cannot depend on it at compile time — see wf006's
//! own mod doc), `contracts/arcane/validate.mjs` (`assertValid`, JSON-schema
//! backed), and `contracts/arcane/authority.mjs` (`payloadClaimsAuthority`).
//! `HostIngestor` here reproduces the exact state machine, ordering, and
//! error codes of the JS `ingest()` method, but takes the structural
//! validation, event classification, receipt-envelope verification, and the
//! "does the payload itself claim authority" check as injected closures
//! (`validate_structure`, `classify`, `verify_receipt`,
//! `payload_claims_authority`) rather than reimplementing those four
//! modules' full logic inside this chunk. A caller wired to real ports of
//! those four modules gets byte-for-byte JS behavior; a caller using a
//! trivial closure (as this file's own unit tests do) exercises the ingest
//! state machine itself, which is what S04's acceptance criteria are about.

use std::collections::BTreeMap;

use super::support::{allow, deny, detail_of, digest_value, ArcCode, Decision, Json};

pub const POST_EFFECT_TYPES: &[&str] = &["post-effect", "post-effect-failure"];

#[derive(Debug, Clone)]
pub struct Effect {
    pub effect_class: String,
    pub target: String,
    pub operation: String,
}

#[derive(Debug, Clone)]
pub struct PriorCorrelation {
    pub request_id: String,
    pub requested_effect: Option<Effect>,
    pub authorized_effect: Option<Effect>,
    pub capability_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultOutcome {
    Success,
    Failure,
    Blocked,
    NoOp,
}

impl ResultOutcome {
    fn as_receipt_result(&self) -> &'static str {
        match self {
            ResultOutcome::Success => "applied",
            ResultOutcome::Failure => "failed",
            ResultOutcome::Blocked => "blocked",
            ResultOutcome::NoOp => "no-op",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EventResult {
    pub outcome: ResultOutcome,
    pub observed_digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HostEvent {
    pub event_id: String,
    pub event_type: String,
    pub effect: Option<Effect>,
    pub run_id: Option<String>,
    pub contract_id: Option<String>,
    pub task_id: Option<String>,
    pub session_id: String,
    pub workspace: String,
    pub source_revision: Option<String>,
    pub prior_correlation: Option<PriorCorrelation>,
    pub result: EventResult,
    pub replay_nonce: String,
    pub replay_sequence: i64,
    pub time: String,
    pub idempotency_key: Option<String>,
    /// Structural-validity flag from the injected `validate_structure`
    /// closure: `true` means the event satisfies `HOST_EVENT_SCHEMA`.
    pub structurally_valid: bool,
    /// True when `extensions` (or any other payload field) itself asserts
    /// authority — mirrors `payloadClaimsAuthority(hostEvent.extensions)`.
    pub payload_claims_authority: bool,
}

#[derive(Debug, Clone)]
pub struct ReceiptEnvelope {
    pub alg: String,
    pub key_id: String,
    pub mac: String,
}

#[derive(Debug, Clone)]
pub struct ConnectionTrust {
    pub issuer_identity: String,
    pub verified_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorityAssertion {
    /// `"model"` | `"host"` | anything else.
    pub asserted_by: String,
    pub receipt: Option<ReceiptEnvelope>,
    pub connection_trust: Option<ConnectionTrust>,
}

#[derive(Debug, Clone)]
pub struct EffectReceipt {
    pub receipt_id: String,
    pub request_id: String,
    pub run_id: String,
    pub contract_id: Option<String>,
    pub task_id: Option<String>,
    pub requested: Option<Effect>,
    pub authorized: Option<Effect>,
    pub observed: Effect,
    pub matched: bool,
    pub actual_diff_digest: Option<String>,
    pub host_event_ref: String,
    pub authentication_method: &'static str, // "capability-signature" | "host-connection-trust"
    pub authentication_key_id: Option<String>,
    pub authentication_issuer_identity: String,
    pub replay_nonce: String,
    pub replay_sequence: i64,
    pub source_revision: String,
    pub idempotency_key: Option<String>,
    pub result: &'static str,
    pub observed_at: String,
}

#[derive(Debug, Clone)]
pub struct IngestOutcome {
    pub accepted: bool,
    pub receipt: Option<EffectReceipt>,
    pub observation_class: Option<String>,
    pub decision: Decision,
}

#[derive(Debug, Clone, PartialEq)]
enum TrustMethod {
    CapabilitySignature { key_id: String },
    HostConnectionTrust { verified_at: Option<String> },
}

#[derive(Debug, Clone)]
struct Trust {
    method: TrustMethod,
    issuer_identity: String,
}

/// Cache entry for delivery-level idempotency. Mirrors JS `#seen`.
struct Seen {
    receipt: Option<EffectReceipt>,
    observation_class: Option<String>,
}

/// Mirrors JS `HostIngestor`. Dependencies the JS constructor takes
/// (`receiptStore`, `replayGuard`, `keyRing`, `policy`, `dependencyLedger`)
/// are represented here as injected closures/callbacks passed per-call
/// (Rust has no ambient mutable-dependency-holding class fields without a
/// trait-object story this chunk does not own), matching each dependency's
/// actual call-site contract in the JS source.
pub struct HostIngestor {
    seen: BTreeMap<String, Seen>,
}

impl Default for HostIngestor {
    fn default() -> Self {
        Self::new()
    }
}

impl HostIngestor {
    pub fn new() -> Self {
        Self { seen: BTreeMap::new() }
    }

    /// Mirrors JS `ingest(hostEvent, { authorityAssertion })`.
    ///
    /// - `classify`: mirrors `classifyObservation(hostEvent, { policy })`.
    /// - `verify_receipt`: mirrors `verifyRecord(hostEvent, receipt,
    ///   { keyRing, boundFields })` — `Ok(())` on verified, `Err(reason)`
    ///   otherwise.
    /// - `replay_check`: mirrors `replayGuard.check({scope, nonce, sequence,
    ///   timestamp})` — `Ok(())` allowed, `Err(decision)` otherwise.
    /// - `mint_receipt_id`: mirrors `mintId('effectReceipt')`.
    /// - `store_append`: mirrors `receiptStore.append(receipt)`.
    /// - `observe_change`: mirrors
    ///   `dependencyLedger.observeChange({dimension:'source-digest', ref,
    ///   digest})`, called only for a mutation-observation with an observed
    ///   digest (WP4 action 10), and only when the ledger is wired (`Some`).
    #[allow(clippy::too_many_arguments)]
    pub fn ingest(
        &mut self,
        event: &HostEvent,
        authority: &AuthorityAssertion,
        classify: impl Fn(&HostEvent) -> String,
        verify_receipt: impl Fn(&HostEvent, &ReceiptEnvelope) -> Result<(), String>,
        mut replay_check: impl FnMut(&HostEvent) -> Result<(), Decision>,
        mint_receipt_id: impl FnOnce() -> String,
        mut store_append: impl FnMut(&EffectReceipt),
        mut observe_change: Option<impl FnMut(&str, &str)>,
    ) -> IngestOutcome {
        // 1. Authority.
        if authority.asserted_by == "model" {
            return Self::refuse(
                None,
                deny(ArcCode::ArcModelSelfReport, "a model self-report is never an effect receipt", detail_of(&[("assertedBy", "model")])),
            );
        }
        if authority.asserted_by != "host" {
            return Self::refuse(
                None,
                deny(
                    ArcCode::ArcHostEventUntrusted,
                    "host ingestion requires an explicit authorityAssertion.assertedBy === \"host\"",
                    detail_of(&[("assertedBy", &authority.asserted_by)]),
                ),
            );
        }

        // 2. Structure.
        if !event.structurally_valid {
            return Self::refuse(None, deny(ArcCode::ArcHostEventInvalid, "host event does not satisfy HOST_EVENT_SCHEMA", detail_of(&[])));
        }

        // 2b. Authority may never be smuggled in through the payload.
        if event.payload_claims_authority {
            return Self::refuse(
                None,
                deny(
                    ArcCode::ArcModelSelfReport,
                    "authority cannot be asserted from within a host event payload, including extensions",
                    detail_of(&[]),
                ),
            );
        }

        // 3. Delivery-level idempotency.
        if let Some(key) = &event.idempotency_key {
            if let Some(cached) = self.seen.get(key) {
                return IngestOutcome {
                    accepted: true,
                    receipt: cached.receipt.clone(),
                    observation_class: cached.observation_class.clone(),
                    decision: allow_duplicate(key),
                };
            }
        }

        // 4. Trust.
        let trust = match Self::resolve_host_trust(event, authority, &verify_receipt) {
            Ok(t) => t,
            Err(d) => return Self::refuse(None, d),
        };

        // 5. Classification.
        let observation_class = classify(event);

        let is_post_effect = POST_EFFECT_TYPES.contains(&event.event_type.as_str());
        if !is_post_effect {
            return IngestOutcome {
                accepted: true,
                receipt: None,
                observation_class: Some(observation_class),
                decision: allow("accepted, no observed effect yet"),
            };
        }

        if event.effect.is_none() {
            return IngestOutcome {
                accepted: true,
                receipt: None,
                observation_class: Some(observation_class),
                decision: allow("accepted, effect deliberately null for this tool"),
            };
        }

        if event.run_id.is_none() {
            return IngestOutcome {
                accepted: true,
                receipt: None,
                observation_class: Some(observation_class),
                decision: allow("accepted, unbound ambient telemetry"),
            };
        }

        if event.source_revision.is_none() {
            return Self::refuse(
                Some(observation_class),
                deny(
                    ArcCode::ArcHostEventInvalid,
                    "a post-effect event must carry an observed effect, sourceRevision, and a run binding (contractId/taskId may be null — ambient tier, amendment A-ER-1)",
                    detail_of(&[("eventId", &event.event_id)]),
                ),
            );
        }

        // 6. Correlation.
        let Some(pc) = &event.prior_correlation else {
            return Self::refuse(
                Some(observation_class),
                deny(
                    ArcCode::ArcIngestCorrelationMissing,
                    "post-effect event has no correlated pre-effect request",
                    detail_of(&[("eventId", &event.event_id)]),
                ),
            );
        };
        if pc.request_id.is_empty() {
            return Self::refuse(
                Some(observation_class),
                deny(
                    ArcCode::ArcIngestCorrelationMissing,
                    "post-effect event has no correlated pre-effect request",
                    detail_of(&[("eventId", &event.event_id)]),
                ),
            );
        }

        // 7. Replay-check.
        if let Err(d) = replay_check(event) {
            return IngestOutcome { accepted: false, receipt: None, observation_class: Some(observation_class), decision: d };
        }

        // Build + persist the receipt.
        let requested = pc.requested_effect.clone().or_else(|| event.effect.clone());
        let authorized_base = pc.authorized_effect.clone().or_else(|| event.effect.clone());
        let observed = event.effect.clone().expect("checked above");

        // Mirrors JS `match`: requested vs. observed only — `authorized` is
        // not part of the comparison.
        let matched = requested
            .as_ref()
            .map(|r| (r.effect_class.as_str(), r.target.as_str(), r.operation.as_str()))
            == Some((observed.effect_class.as_str(), observed.target.as_str(), observed.operation.as_str()));

        let (auth_method, auth_key_id): (&'static str, Option<String>) = match &trust.method {
            TrustMethod::CapabilitySignature { key_id } => ("capability-signature", Some(key_id.clone())),
            TrustMethod::HostConnectionTrust { .. } => ("host-connection-trust", None),
        };

        let receipt = EffectReceipt {
            receipt_id: mint_receipt_id(),
            request_id: pc.request_id.clone(),
            run_id: event.run_id.clone().expect("checked above"),
            contract_id: event.contract_id.clone(),
            task_id: event.task_id.clone(),
            requested,
            authorized: authorized_base,
            observed: observed.clone(),
            matched,
            actual_diff_digest: event.result.observed_digest.clone(),
            host_event_ref: event.event_id.clone(),
            authentication_method: auth_method,
            authentication_key_id: auth_key_id,
            authentication_issuer_identity: trust.issuer_identity.clone(),
            replay_nonce: event.replay_nonce.clone(),
            replay_sequence: event.replay_sequence,
            source_revision: event.source_revision.clone().expect("checked above"),
            idempotency_key: event.idempotency_key.clone(),
            result: event.result.outcome.as_receipt_result(),
            observed_at: event.time.clone(),
        };

        store_append(&receipt);

        if let Some(key) = &event.idempotency_key {
            self.seen.insert(
                key.clone(),
                Seen { receipt: Some(receipt.clone()), observation_class: Some(observation_class.clone()) },
            );
        }

        // 8. WP4 action 10 — an observed mutation invalidates affected evidence.
        if observation_class == "mutation-observation" {
            if let (Some(cb), Some(digest)) = (observe_change.as_mut(), event.result.observed_digest.as_deref()) {
                cb(&observed.target, digest);
            }
        }

        IngestOutcome {
            accepted: true,
            receipt: Some(receipt.clone()),
            observation_class: Some(observation_class),
            decision: allow_detail_receipt(&receipt.receipt_id),
        }
    }

    fn refuse(observation_class: Option<String>, decision: Decision) -> IngestOutcome {
        IngestOutcome { accepted: false, receipt: None, observation_class, decision }
    }

    /// Mirrors JS `#resolveHostTrust`. S00 finding 5 closure: `receipt` must
    /// be structurally a valid auth envelope AND verify; a bare/malformed
    /// value is refused before ever reaching `verify_receipt`.
    fn resolve_host_trust(
        event: &HostEvent,
        authority: &AuthorityAssertion,
        verify_receipt: &impl Fn(&HostEvent, &ReceiptEnvelope) -> Result<(), String>,
    ) -> Result<Trust, Decision> {
        if let Some(receipt) = &authority.receipt {
            if receipt.alg.is_empty() || receipt.key_id.is_empty() || receipt.mac.is_empty() {
                return Err(deny(
                    ArcCode::ArcHostEventUntrusted,
                    "authority=host with a receipt that is not a structurally valid authentication envelope is not authentication (S00 finding 5)",
                    detail_of(&[]),
                ));
            }
            match verify_receipt(event, receipt) {
                Ok(()) => Ok(Trust {
                    method: TrustMethod::CapabilitySignature { key_id: receipt.key_id.clone() },
                    issuer_identity: format!("key:{}", receipt.key_id),
                }),
                Err(reason) => Err(deny(
                    ArcCode::ArcHostEventUntrusted,
                    format!("host receipt failed verification: {reason}"),
                    detail_of(&[]),
                )),
            }
        } else if let Some(ct) = &authority.connection_trust {
            if ct.issuer_identity.is_empty() {
                return Err(deny(ArcCode::ArcHostEventUntrusted, "authority=host asserted with no receipt and no connection-trust proof", detail_of(&[])));
            }
            Ok(Trust {
                method: TrustMethod::HostConnectionTrust { verified_at: ct.verified_at.clone() },
                issuer_identity: ct.issuer_identity.clone(),
            })
        } else {
            Err(deny(ArcCode::ArcHostEventUntrusted, "authority=host asserted with no receipt and no connection-trust proof", detail_of(&[])))
        }
    }
}

fn allow_duplicate(key: &str) -> Decision {
    let mut d = allow("duplicate delivery, cached receipt returned");
    d.detail = detail_of(&[("duplicate", "true"), ("idempotencyKey", key)]);
    d
}

fn allow_detail_receipt(receipt_id: &str) -> Decision {
    let mut d = allow("effect receipt recorded");
    d.detail = detail_of(&[("receiptId", receipt_id)]);
    d
}

#[allow(dead_code)]
fn effect_digest(e: &Effect) -> String {
    digest_value(&Json::Obj(vec![
        ("effectClass".into(), Json::str(e.effect_class.clone())),
        ("target".into(), Json::str(e.target.clone())),
        ("operation".into(), Json::str(e.operation.clone())),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_event() -> HostEvent {
        HostEvent {
            event_id: "evt-1".into(),
            event_type: "post-effect".into(),
            effect: Some(Effect { effect_class: "file-write".into(), target: "/a".into(), operation: "write".into() }),
            run_id: Some("run-1".into()),
            contract_id: None,
            task_id: None,
            session_id: "sess-1".into(),
            workspace: "ws-1".into(),
            source_revision: Some("git:abc".into()),
            prior_correlation: Some(PriorCorrelation {
                request_id: "req-1".into(),
                requested_effect: Some(Effect { effect_class: "file-write".into(), target: "/a".into(), operation: "write".into() }),
                authorized_effect: Some(Effect { effect_class: "file-write".into(), target: "/a".into(), operation: "write".into() }),
                capability_id: Some("cap-1".into()),
            }),
            result: EventResult { outcome: ResultOutcome::Success, observed_digest: Some("sha256:aa".into()) },
            replay_nonce: "n1".into(),
            replay_sequence: 1,
            time: "2026-01-01T00:00:00Z".into(),
            idempotency_key: Some("idem-1".into()),
            structurally_valid: true,
            payload_claims_authority: false,
        }
    }

    fn host_authority_with_trust() -> AuthorityAssertion {
        AuthorityAssertion {
            asserted_by: "host".into(),
            receipt: None,
            connection_trust: Some(ConnectionTrust { issuer_identity: "host:cli".into(), verified_at: None }),
        }
    }

    fn no_op<T>(_x: T) {}

    #[test]
    fn ingest_refuses_model_self_report() {
        let mut ingestor = HostIngestor::new();
        let event = base_event();
        let authority = AuthorityAssertion { asserted_by: "model".into(), receipt: None, connection_trust: None };
        let out = ingestor.ingest(
            &event,
            &authority,
            |_| "mutation-observation".to_string(),
            |_, _| Ok(()),
            |_| Ok(()),
            || "rcpt-1".into(),
            |_| {},
            None::<fn(&str, &str)>,
        );
        assert!(!out.accepted);
        assert_eq!(out.decision.code, Some(ArcCode::ArcModelSelfReport));
    }

    #[test]
    fn ingest_refuses_untrusted_authority_source() {
        let mut ingestor = HostIngestor::new();
        let event = base_event();
        let authority = AuthorityAssertion { asserted_by: "unknown".into(), receipt: None, connection_trust: None };
        let out = ingestor.ingest(&event, &authority, |_| "x".into(), |_, _| Ok(()), |_| Ok(()), || "r".into(), |_| {}, None::<fn(&str, &str)>);
        assert_eq!(out.decision.code, Some(ArcCode::ArcHostEventUntrusted));
    }

    #[test]
    fn ingest_refuses_structurally_invalid_event() {
        let mut ingestor = HostIngestor::new();
        let mut event = base_event();
        event.structurally_valid = false;
        let out = ingestor.ingest(&event, &host_authority_with_trust(), |_| "x".into(), |_, _| Ok(()), |_| Ok(()), || "r".into(), |_| {}, None::<fn(&str, &str)>);
        assert_eq!(out.decision.code, Some(ArcCode::ArcHostEventInvalid));
    }

    #[test]
    fn ingest_refuses_authority_claimed_in_payload() {
        let mut ingestor = HostIngestor::new();
        let mut event = base_event();
        event.payload_claims_authority = true;
        let out = ingestor.ingest(&event, &host_authority_with_trust(), |_| "x".into(), |_, _| Ok(()), |_| Ok(()), || "r".into(), |_| {}, None::<fn(&str, &str)>);
        assert_eq!(out.decision.code, Some(ArcCode::ArcModelSelfReport));
    }

    #[test]
    fn ingest_refuses_untrusted_host_with_no_receipt_or_connection_trust() {
        let mut ingestor = HostIngestor::new();
        let event = base_event();
        let authority = AuthorityAssertion { asserted_by: "host".into(), receipt: None, connection_trust: None };
        let out = ingestor.ingest(&event, &authority, |_| "x".into(), |_, _| Ok(()), |_| Ok(()), || "r".into(), |_| {}, None::<fn(&str, &str)>);
        assert_eq!(out.decision.code, Some(ArcCode::ArcHostEventUntrusted));
    }

    #[test]
    fn ingest_refuses_malformed_receipt_envelope_before_verification() {
        let mut ingestor = HostIngestor::new();
        let event = base_event();
        let authority = AuthorityAssertion {
            asserted_by: "host".into(),
            receipt: Some(ReceiptEnvelope { alg: "".into(), key_id: "k1".into(), mac: "m".into() }),
            connection_trust: None,
        };
        let out = ingestor.ingest(
            &event,
            &authority,
            |_| "x".into(),
            |_, _| panic!("verify_receipt must not be called for a structurally invalid envelope"),
            |_| Ok(()),
            || "r".into(),
            |_| {},
            None::<fn(&str, &str)>,
        );
        assert_eq!(out.decision.code, Some(ArcCode::ArcHostEventUntrusted));
    }

    #[test]
    fn ingest_accepts_lifecycle_event_with_no_receipt_minted() {
        let mut ingestor = HostIngestor::new();
        let mut event = base_event();
        event.event_type = "pre-effect".into();
        let out = ingestor.ingest(&event, &host_authority_with_trust(), |_| "mutation-observation".into(), |_, _| Ok(()), |_| Ok(()), || "r".into(), |_| {}, None::<fn(&str, &str)>);
        assert!(out.accepted);
        assert!(out.receipt.is_none());
    }

    #[test]
    fn ingest_accepts_post_effect_with_null_effect_no_receipt() {
        let mut ingestor = HostIngestor::new();
        let mut event = base_event();
        event.effect = None;
        let out = ingestor.ingest(&event, &host_authority_with_trust(), |_| "x".into(), |_, _| Ok(()), |_| Ok(()), || "r".into(), |_| {}, None::<fn(&str, &str)>);
        assert!(out.accepted);
        assert!(out.receipt.is_none());
    }

    #[test]
    fn ingest_accepts_unbound_ambient_telemetry_with_no_run_id() {
        let mut ingestor = HostIngestor::new();
        let mut event = base_event();
        event.run_id = None;
        let out = ingestor.ingest(&event, &host_authority_with_trust(), |_| "x".into(), |_, _| Ok(()), |_| Ok(()), || "r".into(), |_| {}, None::<fn(&str, &str)>);
        assert!(out.accepted);
        assert!(out.receipt.is_none());
    }

    #[test]
    fn ingest_refuses_post_effect_missing_source_revision() {
        let mut ingestor = HostIngestor::new();
        let mut event = base_event();
        event.source_revision = None;
        let out = ingestor.ingest(&event, &host_authority_with_trust(), |_| "x".into(), |_, _| Ok(()), |_| Ok(()), || "r".into(), |_| {}, None::<fn(&str, &str)>);
        assert_eq!(out.decision.code, Some(ArcCode::ArcHostEventInvalid));
    }

    #[test]
    fn ingest_refuses_missing_correlation() {
        let mut ingestor = HostIngestor::new();
        let mut event = base_event();
        event.prior_correlation = None;
        let out = ingestor.ingest(&event, &host_authority_with_trust(), |_| "x".into(), |_, _| Ok(()), |_| Ok(()), || "r".into(), |_| {}, None::<fn(&str, &str)>);
        assert_eq!(out.decision.code, Some(ArcCode::ArcIngestCorrelationMissing));
    }

    #[test]
    fn ingest_builds_receipt_persists_and_dedupes_idempotency_key() {
        let mut ingestor = HostIngestor::new();
        let event = base_event();
        let mut appended = Vec::new();
        let out1 = ingestor.ingest(
            &event,
            &host_authority_with_trust(),
            |_| "mutation-observation".into(),
            |_, _| Ok(()),
            |_| Ok(()),
            || "receipt-1".into(),
            |r: &EffectReceipt| appended.push(r.receipt_id.clone()),
            None::<fn(&str, &str)>,
        );
        assert!(out1.accepted);
        let r1 = out1.receipt.clone().unwrap();
        assert_eq!(r1.receipt_id, "receipt-1");
        assert!(r1.matched);
        assert_eq!(appended.len(), 1);

        // Redelivery of the exact same idempotency key returns the cached
        // receipt and does not append again.
        let out2 = ingestor.ingest(
            &event,
            &host_authority_with_trust(),
            |_| "mutation-observation".into(),
            |_, _| Ok(()),
            |_| Ok(()),
            || "receipt-should-not-be-used".into(),
            |r: &EffectReceipt| appended.push(r.receipt_id.clone()),
            None::<fn(&str, &str)>,
        );
        assert!(out2.accepted);
        assert_eq!(out2.receipt.unwrap().receipt_id, "receipt-1");
        assert_eq!(appended.len(), 1, "no second append on idempotent replay");
    }

    #[test]
    fn ingest_invokes_observe_change_for_mutation_observation_with_digest() {
        let mut ingestor = HostIngestor::new();
        let event = base_event();
        let mut observed: Vec<(String, String)> = Vec::new();
        let out = ingestor.ingest(
            &event,
            &host_authority_with_trust(),
            |_| "mutation-observation".into(),
            |_, _| Ok(()),
            |_| Ok(()),
            || "receipt-2".into(),
            |_| {},
            Some(|target: &str, digest: &str| observed.push((target.to_string(), digest.to_string()))),
        );
        assert!(out.accepted);
        assert_eq!(observed, vec![("/a".to_string(), "sha256:aa".to_string())]);
    }

    #[test]
    fn ingest_replay_check_failure_refuses_before_persist() {
        let mut ingestor = HostIngestor::new();
        let event = base_event();
        let mut appended = 0;
        let out = ingestor.ingest(
            &event,
            &host_authority_with_trust(),
            |_| "mutation-observation".into(),
            |_, _| Ok(()),
            |_| Err(deny(ArcCode::ArcHostEventInvalid, "replay seen", detail_of(&[]))),
            || "receipt-3".into(),
            |_: &EffectReceipt| appended += 1,
            None::<fn(&str, &str)>,
        );
        assert!(!out.accepted);
        assert_eq!(appended, 0);
    }

    #[test]
    fn effect_digest_is_deterministic() {
        let e = Effect { effect_class: "file-write".into(), target: "/a".into(), operation: "write".into() };
        let d1 = effect_digest(&e);
        let d2 = effect_digest(&e);
        assert_eq!(d1, d2);
        let _ = no_op(d1);
    }
}
