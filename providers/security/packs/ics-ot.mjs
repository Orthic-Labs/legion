// ICS/OT security pack (B7-020). PLC/SCADA/Modbus/OPC-UA source and network
// topology config text only — no PLC connection, no live protocol traffic,
// no operational-network probe of any kind. Every rule is a lexical
// (pattern-only) detector that never certifies an operational deployment as
// safe.

import { digest } from '../contracts.mjs';

const SUPPORT_TIER = 'measured';

const STANDARD_SCOPE = Object.freeze({
  static: true,
  runtime: false,
  description: 'PLC/SCADA source and network topology config text only; no PLC, RTU, historian, or live operational-network connection was made.',
});

const STANDARD_AUTHORITY_LIMITS = Object.freeze([
  'This lens does not establish operational safety, process-safety adequacy, or regulatory adequacy for any standard.',
  'A finding here is an allegation requiring independent adjudication by a qualified OT/ICS engineer with authority over the physical process; it is never a substitute for that decision, and it never authorizes any live probe.',
]);

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function windowAround(text, index, length, radius) {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  return text.slice(start, end);
}

function withMetadata(base, hazards, assumptions) {
  return { ...base, scope: STANDARD_SCOPE, hazards, assumptions, authorityLimits: STANDARD_AUTHORITY_LIMITS };
}

const RULES = [
  {
    id: 'ics-ot.authorization.unauthenticated-write-command',
    severityHint: 'critical',
    claim: 'A PLC/SCADA write command (coil, register, tag) is issued with no visible authentication or role check in the same window.',
    pattern: /\.(?:writeCoil|writeRegister|writeCoils|writeHoldingRegisters|writeTag|writeNode)\s*\(/gi,
    suppressWindowPattern: /authenticate|checkRole|requireRole|isAuthorized|verifyOperator|require\s*\(\s*(?:role|user|operator)/i,
    suppressScope: 'wide',
    hazards: ['An unauthenticated actor with network reach to the control channel can directly change a physical setpoint, coil, or actuator state, with no engineered check on operator authority.'],
    assumptions: ['Authentication enforced at the transport layer (e.g. a VPN or protocol gateway) rather than in this call site is not visible to this lens and must be adjudicated against the actual deployment topology.'],
    effectKind: 'principal-access', effectAction: 'issue-unauthenticated-write', effectScope: 'control-channel',
    chainRoles: ['starter', 'control-bypass', 'impact'],
  },
  {
    id: 'ics-ot.segmentation.ot-bridged-to-corporate-network',
    severityHint: 'critical',
    claim: 'A network/topology config connects an OT/PLC/SCADA service to a corporate or internet-facing network with no visible firewall/DMZ/VLAN reference.',
    pattern: /\b(?:plc|scada|rtu|historian|hmi)\b[\s\S]{0,300}?\b(?:corporate|internet|external|it_network|corp_lan)\b/gi,
    suppressWindowPattern: /firewall|dmz|vlan|segmentation|air[- ]?gap|one[- ]?way|data[- ]?diode/i,
    suppressScope: 'wide',
    hazards: ['A compromise anywhere on the IT/corporate network can pivot directly into the operational network and reach process-control systems, with no engineered segmentation boundary observed.'],
    assumptions: ['A segmentation control implemented outside the text scanned here (a separate firewall appliance config, a network diagram, or a physical air gap) is not visible to this lens and must be adjudicated against the real topology.'],
    effectKind: 'network-reachability', effectAction: 'bridge-it-to-ot', effectScope: 'network-segmentation',
    chainRoles: ['enabler', 'control-bypass'],
  },
  {
    id: 'ics-ot.update-policy.unsigned-plc-firmware-push',
    severityHint: 'high',
    claim: 'A PLC/RTU firmware or logic-program push path has no visible signature or integrity verification.',
    pattern: /\b(?:plc|rtu)[\s\S]{0,200}?\b(?:firmware|program|logic)[\s\S]{0,120}?\b(?:push|download|deploy|flash)\b/gi,
    suppressWindowPattern: /verify|signature|signed|checksum|sha256|hmac/i,
    suppressScope: 'wide',
    hazards: ['An attacker able to reach the engineering/update channel can push unauthorized control logic to a PLC or RTU, directly altering physical-process behavior.'],
    assumptions: ['Verification performed by the vendor engineering-workstation software outside this repository is not visible to this lens and must be adjudicated against the actual update tool.'],
    effectKind: 'code-execution', effectAction: 'push-unverified-logic', effectScope: 'plc-firmware-update',
    chainRoles: ['starter', 'impact'],
  },
];

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `${rule.id}-observation`,
        semanticFeatures: ['ics-ot', rule.id, candidate.detectorMetadata?.file ?? rule.id],
      };
    },
    enumerate(context) {
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-search`, kind: 'lexical-fallback',
          description: `Enumerate every ${rule.id} observation across the denominator.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches: [], coverageGaps: [],
      };
    },
  };
}

const ICS_FILE_PATTERN = /\.(js|mjs|ts|py|cs|st|scl)$|(^|\/)(docker-compose\.ya?ml|.*\.topology\.ya?ml|network\.ya?ml)$/i;

export default Object.freeze({
  id: 'security.ics-ot',
  version: '1.0.0',
  candidateClass: 'ics-ot',
  description: 'Authorization, network segmentation, and update-policy signals in PLC/SCADA source and network topology config text.',
  supportTier: SUPPORT_TIER,
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      if (!ICS_FILE_PATTERN.test(file)) continue;
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      for (const rule of RULES) {
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(text)) !== null) {
          if (match[0].length === 0) { rule.pattern.lastIndex += 1; continue; }
          const window = windowAround(text, match.index, match[0].length, 600);
          if (rule.suppressWindowPattern && rule.suppressWindowPattern.test(window)) continue;

          observations.push({
            ruleId: rule.id,
            candidateClass: 'ics-ot',
            claim: rule.claim,
            severityHint: rule.severityHint,
            sources: [], sinks: artifact ? [artifact.id] : [],
            attackerCapabilities: ['network-position-in-it-or-ot-segment', 'engineering-workstation-access'],
            preconditions: [{
              kind: 'network-reachability', subject: 'actor:external', action: 'reach-control-channel',
              scope: null, environment: 'operational-technology', tenant: null,
            }],
            effects: [{
              kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
              object: artifact?.id ?? null, scope: rule.effectScope, environment: 'operational-technology', tenant: null,
            }],
            assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
            chainRoles: rule.chainRoles,
            evidenceRefs: artifact?.evidenceRefs ?? [],
            detectorMetadata: withMetadata(
              { file, line: lineOf(text, match.index), matchDigest: digest(match[0]) },
              rule.hazards,
              rule.assumptions,
            ),
            uncertainty: [
              'Lexical pattern match only; not confirmed by any protocol capture, PLC connection, or live network probe (none was performed or permitted).',
              'Actual reachability, safety-instrumented-system independence, and process consequence must be adjudicated by a qualified OT engineer.',
            ],
          });
        }
      }
    }
    return observations;
  },
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
