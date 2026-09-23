//! Integration tests for wf070 (`src/lib/verification/arcane/**`).
//!
//! Unit-level regression coverage lives beside each ported module under
//! `src/wf_port/wf070/`; this file exercises the cross-module flow the JS
//! sources are actually used for: route -> create state -> transition ->
//! record a decision -> author + sign a trajectory event -> replay it back
//! from an empty receipt store and land on the identical state fingerprint.
//!
//! NOTE for the integration owner: `legion_policy::wf_port::wf070` is only
//! reachable once `pub mod wf070;` is wired into
//! `src/wf_port/mod.rs` and `pub mod wf_port;`/`pub mod arcane_port;` (the
//! latter already present) are wired into `src/lib.rs`. Until then this
//! file will not compile as part of the crate's test target.

use std::collections::BTreeMap;

use legion_policy::wf_port::wf070::canon::{digest_value, CanonVal};
use legion_policy::wf_port::wf070::event_store::{ArchitectureEventStore, EventProposal, KeyRing, ReceiptStore};
use legion_policy::wf_port::wf070::router::{route_architecture, ArchitectureRouterInput};
use legion_policy::wf_port::wf070::state::create_architecture_state;

struct MemoryReceiptStore(Vec<CanonVal>);
impl ReceiptStore for MemoryReceiptStore {
    fn append(&mut self, event: CanonVal) {
        self.0.push(event);
    }
    fn list(&self) -> &[CanonVal] {
        &self.0
    }
    fn verify_chain(&self) -> Result<(), String> {
        Ok(())
    }
}

struct FixedKeyRing(BTreeMap<String, Vec<u8>>);
impl KeyRing for FixedKeyRing {
    fn get(&self, key_id: &str) -> Option<&[u8]> {
        self.0.get(key_id).map(|v| v.as_slice())
    }
}

fn ledger() -> CanonVal {
    CanonVal::obj()
        .set("schema", CanonVal::Str("acceptance-ledger.v1".to_string()))
        .set("ledger_version", CanonVal::Int(1))
        .set("intent_epoch", CanonVal::Int(1))
        .set("acceptance_fingerprint", CanonVal::Str(digest_value(&CanonVal::obj())))
        .set("frozen_at", CanonVal::Null)
        .set("items", CanonVal::Arr(vec![]))
}

#[test]
fn route_then_transition_then_replay_round_trips() {
    // 1. Route a significant, non-critical change: D1/standard.
    let mut significance = std::collections::BTreeSet::new();
    significance.insert("broad_impact".to_string());
    let route = route_architecture(&ArchitectureRouterInput { significance, ..Default::default() }).unwrap();
    assert_eq!(route.depth, "D1");
    assert_eq!(route.rigor, "standard");

    // 2. Create initial state and open an authenticated event store.
    let initial = create_architecture_state("lineage-wf070", ledger(), "budget-wf070").unwrap();
    let mut store = MemoryReceiptStore(vec![]);
    let mut keys = BTreeMap::new();
    keys.insert("k1".to_string(), b"wf070-integration-test-key".to_vec());
    let key_ring = FixedKeyRing(keys);
    let mut event_store =
        ArchitectureEventStore::new(&mut store, &key_ring, "k1", Box::new(|| "2026-09-23T00:00:00Z".to_string())).unwrap();

    let replayed = event_store.replay("lineage-wf070", &initial).unwrap();
    assert_eq!(replayed.event_count, 0);

    // 3. Record the route, then transition, then a decision — three
    //    accepted events forming a real trajectory.
    let route_event = EventProposal {
        objective_lineage_id: "lineage-wf070".to_string(),
        intent_epoch: 1,
        execution_id: "exec-wf070".to_string(),
        repository_id: "repo-wf070".to_string(),
        actor_role: "legion".to_string(),
        phase: "route".to_string(),
        event_type: "ROUTE_CLASSIFIED".to_string(),
        payload: CanonVal::obj().set("objective", CanonVal::Str(route.objective.clone())).set("depth", CanonVal::Str(route.depth.to_string())),
        acceptance_ids: vec![],
        decision_ids: vec![],
        finding_ids: vec![],
        input_fingerprint: None,
        output_refs: vec![],
        checkpoint_ref: None,
        cost_delta: CanonVal::obj(),
        retry_class: "none".to_string(),
        terminal_reason: None,
        privacy_class: "content_free".to_string(),
    };
    let after_route = event_store.accept(&route_event, Some(replayed.state_fingerprint.as_str())).unwrap();
    assert_eq!(after_route.last_sequence, 1);

    let mut transition_event = route_event.clone_with_type("ARCHITECTURE_TRANSITIONED", CanonVal::obj().set("from", CanonVal::Str("UNROUTED".into())).set("to", CanonVal::Str("TAILORED".into())));
    transition_event.phase = "decide".to_string();
    let after_transition = event_store.accept(&transition_event, Some(after_route.state_fingerprint.as_str())).unwrap();
    assert_eq!(after_transition.last_sequence, 2);
    assert_eq!(
        after_transition.state.get("task").unwrap().get("architecture_status").unwrap().as_str(),
        Some("TAILORED")
    );

    let decision_event = route_event.clone_with_type("DECISION_RECORDED", CanonVal::obj().set("id", CanonVal::Str("D-1".into())).set("summary", CanonVal::Str("adopt option A".into())));
    let after_decision = event_store.accept(&decision_event, Some(after_transition.state_fingerprint.as_str())).unwrap();
    assert_eq!(after_decision.last_sequence, 3);
    assert_eq!(after_decision.state.get("decision").unwrap().get("items").unwrap().as_arr().unwrap().len(), 1);

    // 4. A fresh store replaying the same events from the same initial
    //    state must land on the identical final state fingerprint —
    //    the whole point of an authenticated trajectory.
    drop(event_store);
    let mut event_store2 = ArchitectureEventStore::new(&mut store, &key_ring, "k1", Box::new(|| "2026-09-23T00:00:00Z".to_string())).unwrap();
    let replayed2 = event_store2.replay("lineage-wf070", &initial).unwrap();
    assert_eq!(replayed2.event_count, 3);
    assert_eq!(replayed2.state_fingerprint, after_decision.state_fingerprint);
    assert_eq!(
        replayed2.state.get("task").unwrap().get("architecture_status").unwrap().as_str(),
        Some("TAILORED")
    );
}

// Small local helper trait to keep the test above readable: build a sibling
// proposal that only changes `event_type`/`payload`/(optionally `phase`).
trait ProposalClone {
    fn clone_with_type(&self, event_type: &str, payload: CanonVal) -> EventProposal;
}
impl ProposalClone for EventProposal {
    fn clone_with_type(&self, event_type: &str, payload: CanonVal) -> EventProposal {
        EventProposal {
            objective_lineage_id: self.objective_lineage_id.clone(),
            intent_epoch: self.intent_epoch,
            execution_id: self.execution_id.clone(),
            repository_id: self.repository_id.clone(),
            actor_role: self.actor_role.clone(),
            phase: self.phase.clone(),
            event_type: event_type.to_string(),
            payload,
            acceptance_ids: self.acceptance_ids.clone(),
            decision_ids: self.decision_ids.clone(),
            finding_ids: self.finding_ids.clone(),
            input_fingerprint: self.input_fingerprint.clone(),
            output_refs: self.output_refs.clone(),
            checkpoint_ref: self.checkpoint_ref.clone(),
            cost_delta: self.cost_delta.clone(),
            retry_class: self.retry_class.clone(),
            terminal_reason: self.terminal_reason.clone(),
            privacy_class: self.privacy_class.clone(),
        }
    }
}
