#![forbid(unsafe_code)]

//! Legion's declarations over the RightKit evidence packages: state root,
//! key ring, handoff prompts and report branding. Every Legion binary calls
//! [`declare`] once at start-up, before any package reads its identity.

use rightkit_agent_orchestration_handoff::{set_handoff_host, HandoffHost};
use rightkit_evidence_contracts::state_root::{set_state_identity, StateIdentity};
use rightkit_evidence_governance::key_ring::{set_key_ring_identity, KeyRingIdentity};
use rightkit_evidence_report::{set_report_branding, ReportBranding};

/// Declare Legion's identity to the RightKit packages. The first call wins.
pub fn declare() {
    set_state_identity(StateIdentity {
        env_var: "LEGION_STATE_ROOT".into(),
        vendor_dir: "Orthic Labs".into(),
        app_dir: "Legion".into(),
        xdg_dir: "legion".into(),
    });
    set_key_ring_identity(KeyRingIdentity {
        env_var: "ARCANE_KEY_DIR".into(),
        home_relative_dir: vec![".codex".into(), "arcane-keys".into()],
        init_command: "legion keys init".into(),
    });
    set_handoff_host(HandoffHost {
        program: "legion".into(),
        script_verb: "script".into(),
        product: "Legion".into(),
    });
    set_report_branding(ReportBranding {
        tool_name: "Legion".into(),
        information_uri: "https://github.com/Orthic-Labs/legion".into(),
        title: "Legion Report".into(),
    });
}
