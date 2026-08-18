// Applicability-bound safety hazard scanner (B7-020). Repository/config text
// only — no device, chain, or operational-network connection; no live probe
// of any kind. Each domain rule only fires when its trigger pattern is
// present in the denominator (applicability-bound); when it fires, the
// surrounding window is inspected for interlock, failsafe, degraded-mode,
// emergency-stop, human-override, confirmation, and recovery/incident
// signals to select one of the seven required dispositions
// (positive/mitigated/blocked/unsafe-degraded/missing-interlock/
// human-override/clean — 'clean' is simply "no trigger match").
//
// This module is intentionally separate from providers/security/**: it does
// not build a security-surface-model, does not produce a SecurityCandidateV2,
// and never routes through candidate-engine.mjs. Every hazard it returns is
// built via createHazardCandidate, which hard-codes
// reasoningRequirement: 'human-decision' and certifiable: false.

import { createHazardCandidate, assertHazard } from './hazard-model.mjs';
import { digest } from './contracts.mjs';

// Shared, domain-agnostic signal vocabulary. Deliberately distinct
// function/flag-shaped keywords (not free-text) so detection is
// deterministic and fixture-testable, the same way the existing security
// packs key off named APIs rather than natural-language comments.
const BLOCKED_PATTERN = /hazardActionBlocked\s*\(|preconditionFailed\s*\(\s*\)|refuseAction\s*\(/;
const UNSAFE_DEGRADED_PATTERN = /degradedModeUnsafe\s*\(|failOpen\s*\(|degradedMode\s*[:=]\s*["']unsafe["']/;
const MISSING_INTERLOCK_PATTERN = /interlockBypassed\s*\(|skipInterlock\s*\(|disableInterlock\s*\(/;
const HUMAN_OVERRIDE_PATTERN = /humanOverrideGranted\s*\(|operatorOverrideToken|requireHumanApproval\s*\(\s*\)\s*\.\s*granted/;
const MITIGATED_PATTERN = /interlockEnforced\s*\(|confirmationRequired\s*\(\s*\)\s*===\s*true|limitCheckPassed\s*\(/;
const EMERGENCY_STOP_PATTERN = /emergencyStopEngaged\s*\(|eStopTriggered\s*\(/;
const RECOVERY_PATTERN = /backupVerified\s*\(|recoveryPointConfirmed\s*\(|hasRecentBackup\s*\(\s*\)\s*===\s*true/;
const INCIDENT_PATTERN = /incidentResponsePlan\s*\(|pagerDutyAlert\s*\(|onCallNotified\s*\(/;

const STANDARD_SCOPE = Object.freeze({
  static: true,
  runtime: false,
  description: 'Repository source/config text only; no device, chain, operational network, or live system connection was made.',
});

function windowAround(text, index, length, radius = 500) {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  return text.slice(start, end);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

// Classifies one trigger match into a disposition plus the field values that
// go with it. This is the shared decision table every domain rule uses.
function classify(window) {
  if (BLOCKED_PATTERN.test(window)) {
    return {
      disposition: 'blocked', severityHint: 'low',
      interlock: 'present', failsafeDefault: 'safe', confirmation: 'present',
      note: 'A precondition/refusal guard is present in the surrounding window; the hazard action appears to be blocked before execution.',
    };
  }
  if (UNSAFE_DEGRADED_PATTERN.test(window)) {
    return {
      disposition: 'unsafe-degraded', severityHint: 'critical',
      interlock: 'missing', failsafeDefault: 'unsafe', degradedMode: 'unsafe', confirmation: 'absent',
      note: 'A degraded-mode/fail-open signal is present in the surrounding window; the observed fallback behavior is itself unsafe.',
    };
  }
  if (MISSING_INTERLOCK_PATTERN.test(window)) {
    return {
      disposition: 'missing-interlock', severityHint: 'critical',
      interlock: 'missing', failsafeDefault: 'unsafe', confirmation: 'absent',
      note: 'An explicit interlock-bypass/skip signal is present in the surrounding window; an interlock exists elsewhere but is disabled on this path.',
    };
  }
  if (HUMAN_OVERRIDE_PATTERN.test(window)) {
    return {
      disposition: 'human-override', severityHint: 'medium',
      interlock: 'present', failsafeDefault: 'safe', humanOverride: 'required-and-present', confirmation: 'present',
      note: 'A human-override-granted signal is present in the surrounding window; the action proceeds only after an observed human override.',
    };
  }
  if (MITIGATED_PATTERN.test(window)) {
    return {
      disposition: 'mitigated', severityHint: 'medium',
      interlock: 'present', failsafeDefault: 'safe', confirmation: 'present',
      note: 'An interlock/confirmation/limit-check signal is present in the surrounding window; treated as a mitigating control pending adjudication.',
    };
  }
  return {
    disposition: 'positive', severityHint: 'high',
    interlock: 'missing', failsafeDefault: 'unknown', confirmation: 'absent',
    note: 'No interlock, confirmation, override, blocking, or degraded-mode signal was found in the surrounding window.',
  };
}

const DOMAINS = [
  {
    id: 'physical.direct-actuator-command',
    outcomeClass: 'physical',
    ruleId: 'safety.physical.direct-actuator-command',
    trigger: /\b(?:actuator|motor|valve|relay|servo)\.(?:start|open|close|enable|drive)\s*\(/g,
    claim: 'A direct physical actuator/motor/valve/relay command is issued in this code path.',
    hazards: ['Uncontrolled actuation can cause crushing, entrapment, thermal, or other bodily-injury hazards to a nearby operator or bystander.'],
    assumptions: ['Whether this call path is reachable from an untrusted, remote, or automated input (rather than a supervised local operator) is not established by this lens; only the local command site is observed.'],
    misuseScenarios: ['An attacker or malfunctioning upstream system could invoke this command repeatedly or out of sequence to cause mechanical damage or an unsafe physical state.'],
    unsafeState: 'uncontrolled-physical-actuation',
    trackEmergencyStop: true,
  },
  {
    id: 'medical.dose-administration',
    outcomeClass: 'medical',
    ruleId: 'safety.medical.dose-administration',
    trigger: /\b(?:administerDose|infusionPump\.(?:start|set)|insulinPump\.deliver)\s*\(/g,
    claim: 'A medical-device dosing/administration action is issued in this code path.',
    hazards: ['An unmitigated or unchecked dosing command can cause patient over-dose, under-dose, or a missed-therapy adverse event.'],
    assumptions: ['Dose-range validation performed by device firmware or a separate clinical-decision-support layer outside this repository is not observed by this lens.'],
    misuseScenarios: ['A compromised or misconfigured caller could issue a dosing command outside clinically safe bounds, or repeat a dose that should be one-time only.'],
    unsafeState: 'unchecked-dose-administration',
  },
  {
    id: 'financial.irreversible-transfer',
    outcomeClass: 'financial',
    ruleId: 'safety.financial.irreversible-transfer',
    trigger: /\b(?:transferFunds|executePayment|initiateWithdrawal|sendPayment)\s*\(/g,
    claim: 'An irreversible funds-transfer or payment action is issued in this code path.',
    hazards: ['An unmitigated funds transfer executed in error, under attacker control, or against a compromised account can cause an irrecoverable financial loss to the account holder.'],
    assumptions: ['Bank/network-side reversal or fraud-hold mechanisms outside this repository are not observed by this lens; the transfer is treated as irreversible from the application\'s own perspective.'],
    misuseScenarios: ['An attacker with API access or a compromised session could trigger unauthorized transfers, or replay a transfer request to move funds multiple times.'],
    unsafeState: 'unmitigated-funds-transfer',
    trackIncidentControls: true,
  },
  {
    id: 'child-facing.minor-data-collection',
    outcomeClass: 'child-facing',
    ruleId: 'safety.child-facing.minor-data-collection',
    trigger: /\b(?:collectChildData|saveChildProfile|storeMinorData)\s*\(/g,
    claim: 'Personal data belonging to a child/minor user is collected or stored in this code path.',
    hazards: ['Collecting or storing a minor\'s personal data without a verified parental-consent gate creates a child-safety and privacy exposure, and a durable record that cannot be un-collected after the fact.'],
    assumptions: ['A parental-consent verification flow implemented in a separate service or vendor integration outside this repository is not observed by this lens.'],
    misuseScenarios: ['An attacker or a minor misrepresenting their age could cause child data to be collected and retained without a guardian ever consenting.'],
    unsafeState: 'unconsented-minor-data-collection',
  },
  {
    id: 'operational.production-disruption-command',
    outcomeClass: 'operational',
    ruleId: 'safety.operational.production-disruption-command',
    trigger: /\b(?:scaleDownCluster|shutdownProductionService|drainNode|terminateInstance)\s*\(/g,
    claim: 'A production-infrastructure operational command (shutdown/scale-down/drain/terminate) is issued in this code path.',
    hazards: ['An unmitigated operational command executed against production can cause a service outage affecting every dependent user or downstream system.'],
    assumptions: ['A staging/dry-run gate or change-management approval enforced by a separate deployment platform outside this repository is not observed by this lens.'],
    misuseScenarios: ['An attacker with deploy/ops access, or a misfiring automation, could trigger this command against the wrong target or at the wrong time, causing an avoidable outage.'],
    unsafeState: 'unmitigated-production-disruption',
    trackEmergencyStop: true,
    trackIncidentControls: true,
  },
  {
    id: 'irreversible.destructive-account-action',
    outcomeClass: 'irreversible',
    ruleId: 'safety.irreversible.destructive-account-action',
    trigger: /\b(?:factoryReset|permanentBan|purgeAccount|hardDelete)\s*\(/g,
    claim: 'An irreversible state-destroying action (factory reset, permanent ban, account purge, hard delete) is issued in this code path.',
    hazards: ['An irreversible action executed in error, under attacker control, or without confirmed operator intent cannot be undone by any recovery mechanism this lens observed.'],
    assumptions: ['A soft-delete/undo window or administrative reversal process implemented elsewhere is not observed by this lens; the action is treated as irreversible from this call site.'],
    misuseScenarios: ['An attacker who gains the calling privilege, or a scripting error that iterates over the wrong record set, could trigger irreversible destruction at scale.'],
    unsafeState: 'unmitigated-irreversible-action',
    trackRecovery: true,
  },
  {
    id: 'catastrophic-data-loss.bulk-destructive-operation',
    outcomeClass: 'catastrophic-data-loss',
    ruleId: 'safety.catastrophic-data-loss.bulk-destructive-operation',
    trigger: /\b(?:truncateTable|dropDatabase|deleteAllRecords|wipeVolume)\s*\(/g,
    claim: 'A bulk/catastrophic data-destroying operation (truncate, drop, delete-all, wipe) is issued in this code path.',
    hazards: ['A catastrophic bulk-delete executed without a verified backup/recovery path can cause permanent, unrecoverable loss of the entire dataset.'],
    assumptions: ['A point-in-time-recovery or replicated-backup system operated outside this repository is not observed by this lens; recovery is only credited when a local verification call is present.'],
    misuseScenarios: ['An attacker with database credentials, or an operator running the wrong script against production, could trigger irreversible data loss for every tenant sharing the target.'],
    unsafeState: 'unverified-bulk-data-destruction',
    trackRecovery: true,
    trackIncidentControls: true,
  },
];

export const SAFETY_RULE_IDS = Object.freeze(DOMAINS.map((d) => d.ruleId));

export function scanSafetyHazards({ files, readFile, denominatorDigest }) {
  const hazards = [];
  for (const domain of DOMAINS) {
    let applicable = false;
    for (const file of files ?? []) {
      const text = readFile(file) ?? '';
      if (!text) continue;
      domain.trigger.lastIndex = 0;
      let match;
      while ((match = domain.trigger.exec(text)) !== null) {
        if (match[0].length === 0) { domain.trigger.lastIndex += 1; continue; }
        applicable = true;
        const window = windowAround(text, match.index, match[0].length);
        const classification = classify(window);
        const evidenceRef = digest({ domain: domain.id, file, index: match.index, denominatorDigest });

        const hazard = createHazardCandidate({
          domain: domain.id,
          outcomeClass: domain.outcomeClass,
          ruleId: domain.ruleId,
          claim: domain.claim,
          severityHint: classification.severityHint,
          scope: STANDARD_SCOPE,
          hazards: domain.hazards,
          assumptions: domain.assumptions,
          authorityLimits: [
            'This lens does not establish physical, medical, financial, child-safety, operational, or data-recovery adequacy under any standard.',
            'A hazard here is an allegation requiring a qualified domain-authority human decision; it is never closable by a model or automated verdict.',
          ],
          disposition: classification.disposition,
          unsafeStates: classification.disposition === 'clean' ? [] : [domain.unsafeState],
          interlock: classification.interlock ?? 'not-applicable',
          failsafeDefault: classification.failsafeDefault ?? 'unknown',
          degradedMode: classification.degradedMode ?? 'not-applicable',
          emergencyStop: domain.trackEmergencyStop
            ? (EMERGENCY_STOP_PATTERN.test(window) ? 'present' : 'absent')
            : 'not-applicable',
          humanOverride: classification.humanOverride ?? 'not-applicable',
          confirmation: classification.confirmation ?? 'not-applicable',
          misuseScenarios: domain.misuseScenarios,
          recoveryPath: domain.trackRecovery
            ? (RECOVERY_PATTERN.test(window) ? 'defined' : 'absent')
            : 'not-applicable',
          incidentControls: domain.trackIncidentControls
            ? (INCIDENT_PATTERN.test(window) ? 'defined' : 'absent')
            : 'not-applicable',
          evidenceRefs: [evidenceRef],
          detectorMetadata: {
            file,
            line: lineOf(text, match.index),
            matchDigest: digest(match[0]),
            classificationNote: classification.note,
          },
          uncertainty: [
            'Lexical pattern match only; not confirmed by device, clinical, financial-ledger, guardian-consent, operational, or backup-system verification (none was performed or permitted).',
            'Whether this call site is reachable in a live deployment, and by whom, must be adjudicated by a qualified domain-authority human, never by this lens.',
          ],
        });
        assertHazard(hazard);
        hazards.push(hazard);
      }
    }
  }
  return hazards;
}

export { DOMAINS as SAFETY_DOMAINS };
