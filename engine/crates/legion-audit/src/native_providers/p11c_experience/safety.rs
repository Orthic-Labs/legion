//! Retained items of the safety port: `safety_rule_ids` and its domain table
//! (no production caller). Scanner, hazard-model and closure logic reachable
//! only from deleted tests was removed in the native-provider sweep.
struct SafetyDomain {
    id: &'static str,
    outcome_class: &'static str,
    rule_id: &'static str,
    trigger: &'static str,
    claim: &'static str,
    hazards: &'static [&'static str],
    assumptions: &'static [&'static str],
    misuse_scenarios: &'static [&'static str],
    unsafe_state: &'static str,
    track_emergency_stop: bool,
    track_recovery: bool,
    track_incident_controls: bool,
}

fn domains() -> Vec<SafetyDomain> {
    vec![
        SafetyDomain {
            id: "physical.direct-actuator-command", outcome_class: "physical", rule_id: "safety.physical.direct-actuator-command",
            trigger: r"\b(?:actuator|motor|valve|relay|servo)\.(?:start|open|close|enable|drive)\s*\(",
            claim: "A direct physical actuator/motor/valve/relay command is issued in this code path.",
            hazards: &["Uncontrolled actuation can cause crushing, entrapment, thermal, or other bodily-injury hazards to a nearby operator or bystander."],
            assumptions: &["Whether this call path is reachable from an untrusted, remote, or automated input (rather than a supervised local operator) is not established by this lens; only the local command site is observed."],
            misuse_scenarios: &["An attacker or malfunctioning upstream system could invoke this command repeatedly or out of sequence to cause mechanical damage or an unsafe physical state."],
            unsafe_state: "uncontrolled-physical-actuation", track_emergency_stop: true, track_recovery: false, track_incident_controls: false,
        },
        SafetyDomain {
            id: "medical.dose-administration", outcome_class: "medical", rule_id: "safety.medical.dose-administration",
            trigger: r"\b(?:administerDose|infusionPump\.(?:start|set)|insulinPump\.deliver)\s*\(",
            claim: "A medical-device dosing/administration action is issued in this code path.",
            hazards: &["An unmitigated or unchecked dosing command can cause patient over-dose, under-dose, or a missed-therapy adverse event."],
            assumptions: &["Dose-range validation performed by device firmware or a separate clinical-decision-support layer outside this repository is not observed by this lens."],
            misuse_scenarios: &["A compromised or misconfigured caller could issue a dosing command outside clinically safe bounds, or repeat a dose that should be one-time only."],
            unsafe_state: "unchecked-dose-administration", track_emergency_stop: false, track_recovery: false, track_incident_controls: false,
        },
        SafetyDomain {
            id: "financial.irreversible-transfer", outcome_class: "financial", rule_id: "safety.financial.irreversible-transfer",
            trigger: r"\b(?:transferFunds|executePayment|initiateWithdrawal|sendPayment)\s*\(",
            claim: "An irreversible funds-transfer or payment action is issued in this code path.",
            hazards: &["An unmitigated funds transfer executed in error, under attacker control, or against a compromised account can cause an irrecoverable financial loss to the account holder."],
            assumptions: &["Bank/network-side reversal or fraud-hold mechanisms outside this repository are not observed by this lens; the transfer is treated as irreversible from the application's own perspective."],
            misuse_scenarios: &["An attacker with API access or a compromised session could trigger unauthorized transfers, or replay a transfer request to move funds multiple times."],
            unsafe_state: "unmitigated-funds-transfer", track_emergency_stop: false, track_recovery: false, track_incident_controls: true,
        },
        SafetyDomain {
            id: "child-facing.minor-data-collection", outcome_class: "child-facing", rule_id: "safety.child-facing.minor-data-collection",
            trigger: r"\b(?:collectChildData|saveChildProfile|storeMinorData)\s*\(",
            claim: "Personal data belonging to a child/minor user is collected or stored in this code path.",
            hazards: &["Collecting or storing a minor's personal data without a verified parental-consent gate creates a child-safety and privacy exposure, and a durable record that cannot be un-collected after the fact."],
            assumptions: &["A parental-consent verification flow implemented in a separate service or vendor integration outside this repository is not observed by this lens."],
            misuse_scenarios: &["An attacker or a minor misrepresenting their age could cause child data to be collected and retained without a guardian ever consenting."],
            unsafe_state: "unconsented-minor-data-collection", track_emergency_stop: false, track_recovery: false, track_incident_controls: false,
        },
        SafetyDomain {
            id: "operational.production-disruption-command", outcome_class: "operational", rule_id: "safety.operational.production-disruption-command",
            trigger: r"\b(?:scaleDownCluster|shutdownProductionService|drainNode|terminateInstance)\s*\(",
            claim: "A production-infrastructure operational command (shutdown/scale-down/drain/terminate) is issued in this code path.",
            hazards: &["An unmitigated operational command executed against production can cause a service outage affecting every dependent user or downstream system."],
            assumptions: &["A staging/dry-run gate or change-management approval enforced by a separate deployment platform outside this repository is not observed by this lens."],
            misuse_scenarios: &["An attacker with deploy/ops access, or a misfiring automation, could trigger this command against the wrong target or at the wrong time, causing an avoidable outage."],
            unsafe_state: "unmitigated-production-disruption", track_emergency_stop: true, track_recovery: false, track_incident_controls: true,
        },
        SafetyDomain {
            id: "irreversible.destructive-account-action", outcome_class: "irreversible", rule_id: "safety.irreversible.destructive-account-action",
            trigger: r"\b(?:factoryReset|permanentBan|purgeAccount|hardDelete)\s*\(",
            claim: "An irreversible state-destroying action (factory reset, permanent ban, account purge, hard delete) is issued in this code path.",
            hazards: &["An irreversible action executed in error, under attacker control, or without confirmed operator intent cannot be undone by any recovery mechanism this lens observed."],
            assumptions: &["A soft-delete/undo window or administrative reversal process implemented elsewhere is not observed by this lens; the action is treated as irreversible from this call site."],
            misuse_scenarios: &["An attacker who gains the calling privilege, or a scripting error that iterates over the wrong record set, could trigger irreversible destruction at scale."],
            unsafe_state: "unmitigated-irreversible-action", track_emergency_stop: false, track_recovery: true, track_incident_controls: false,
        },
        SafetyDomain {
            id: "catastrophic-data-loss.bulk-destructive-operation", outcome_class: "catastrophic-data-loss", rule_id: "safety.catastrophic-data-loss.bulk-destructive-operation",
            trigger: r"\b(?:truncateTable|dropDatabase|deleteAllRecords|wipeVolume)\s*\(",
            claim: "A bulk/catastrophic data-destroying operation (truncate, drop, delete-all, wipe) is issued in this code path.",
            hazards: &["A catastrophic bulk-delete executed without a verified backup/recovery path can cause permanent, unrecoverable loss of the entire dataset."],
            assumptions: &["A point-in-time-recovery or replicated-backup system operated outside this repository is not observed by this lens; recovery is only credited when a local verification call is present."],
            misuse_scenarios: &["An attacker with database credentials, or an operator running the wrong script against production, could trigger irreversible data loss for every tenant sharing the target."],
            unsafe_state: "unverified-bulk-data-destruction", track_emergency_stop: false, track_recovery: true, track_incident_controls: true,
        },
    ]
}

pub fn safety_rule_ids() -> Vec<&'static str> {
    domains().into_iter().map(|d| d.rule_id).collect()
}
