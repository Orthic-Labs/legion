// Smart-contract security pack (B7-020). Solidity/Vyper source text only —
// no chain connection, no RPC call, no transaction simulation, no deployed
// bytecode inspection. Every rule is a lexical (pattern-only) detector that
// never certifies a contract as safe and never emits a candidate without a
// stated scope/hazards/assumptions/authority-limits block.

import { digest } from '../contracts.mjs';

const SUPPORT_TIER = 'measured';

const STANDARD_SCOPE = Object.freeze({
  static: true,
  runtime: false,
  description: 'Contract source text only; no chain, RPC, mempool, or deployed-bytecode connection was made.',
});

const STANDARD_AUTHORITY_LIMITS = Object.freeze([
  'This lens does not establish contract safety, audit completeness, or fitness for mainnet deployment under any standard.',
  'A finding here is an allegation requiring independent adjudication, ideally including a funded on-chain or fork-based proof; it is never a substitute for a qualified smart-contract auditor decision.',
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
    id: 'smart-contract.access-control.tx-origin-authorization',
    severityHint: 'high',
    claim: 'A privileged check authorizes the caller using `tx.origin` instead of `msg.sender`.',
    pattern: /require\s*\(\s*tx\.origin\s*==|tx\.origin\s*==\s*owner/gi,
    suppressPattern: null,
    hazards: ['A phishing contract can relay a privileged call through a victim EOA, since `tx.origin` reflects the original signer rather than the immediate caller.'],
    assumptions: ['The comparison target is treated as a privileged/owner check; a non-privileged use of `tx.origin` would be a false positive requiring adjudication.'],
    effectKind: 'principal-access', effectAction: 'authorize', effectScope: 'tx-origin-check',
    chainRoles: ['starter', 'control-bypass'],
  },
  {
    id: 'smart-contract.access-control.privileged-function-unprotected',
    severityHint: 'high',
    claim: 'A privileged-looking function (mint/burn/withdraw/pause/setOwner/upgrade) has no visible access-control modifier or require check.',
    pattern: /function\s+(?:mint|burn|withdraw|pause|unpause|setOwner|setAdmin|sweep|rescue|selfdestruct|kill)\s*\([^)]*\)\s*(?:external|public)/gi,
    suppressWindowPattern: /onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender\s*==|AccessControl|Ownable/i,
    suppressScope: 'signature-and-body',
    hazards: ['Any external account may call a state-changing privileged function directly, with no on-chain access gate observed.'],
    assumptions: ['The function name heuristic is a naming convention, not a semantic guarantee; a differently-named privileged function is not detected, and a benign use of one of these names is a false positive requiring adjudication.'],
    effectKind: 'principal-access', effectAction: 'invoke-privileged-function', effectScope: 'unprotected-function',
    chainRoles: ['starter', 'privilege-escalation'],
  },
  {
    id: 'smart-contract.reentrancy.external-call-before-guard',
    severityHint: 'high',
    claim: 'An external value-transferring call is present with no visible reentrancy guard in the same function context.',
    pattern: /\.call\{\s*value\s*:[^}]*\}\s*\(|\.call\.value\s*\([^)]*\)\s*\(/gi,
    suppressWindowPattern: /nonReentrant|ReentrancyGuard|checks-effects-interactions/i,
    suppressScope: 'wide',
    hazards: ['A malicious callee (including a fallback function) can re-enter the calling function before state is finalized, potentially draining funds or corrupting invariants.'],
    assumptions: ['Checks-effects-interactions ordering performed without a named guard or comment is not detected by this lexical lens and must be adjudicated from the full function body.'],
    effectKind: 'code-execution', effectAction: 'reenter', effectScope: 'external-call',
    chainRoles: ['enabler', 'impact'],
  },
  {
    id: 'smart-contract.oracle.single-source-price-trust',
    severityHint: 'high',
    claim: 'A price/oracle read is used with no visible staleness or deviation check in the same window.',
    pattern: /\.latestAnswer\s*\(\s*\)|\.latestRoundData\s*\(\s*\)|getPrice\s*\(\s*\)/gi,
    suppressWindowPattern: /updatedAt|heartbeat|deviation|TWAP|twap|require\s*\([^)]*(?:stale|fresh)/i,
    suppressScope: 'wide',
    hazards: ['An unchecked or manipulable price feed can be used to trigger favorable liquidations, mints, or trades against the protocol.'],
    assumptions: ['Whether the oracle is a single source (spot) or an aggregated/TWAP feed configured elsewhere is not observed by this lens; only the local read-site check is examined.'],
    effectKind: 'integrity-impact', effectAction: 'trust-unchecked-price', effectScope: 'oracle-read',
    chainRoles: ['starter', 'impact'],
  },
  {
    id: 'smart-contract.upgradeability.unprotected-upgrade-authorization',
    severityHint: 'critical',
    claim: 'An upgrade entrypoint (`upgradeTo`/`_authorizeUpgrade`) has no visible access-control modifier or require check.',
    pattern: /function\s+upgradeTo(?:AndCall)?\s*\([^)]*\)|_authorizeUpgrade\s*\([^)]*\)\s*(?:internal|override)/gi,
    suppressWindowPattern: /onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender\s*==/i,
    suppressScope: 'signature-and-body',
    hazards: ['An unauthorized caller can point the proxy at an arbitrary implementation, taking full control of contract logic and stored funds.'],
    assumptions: ['Access control enforced via a modifier applied at the contract level (rather than inline in the function) is not visible to a per-function window and must be adjudicated.'],
    effectKind: 'code-execution', effectAction: 'replace-implementation', effectScope: 'proxy-upgrade',
    chainRoles: ['starter', 'privilege-escalation', 'impact'],
  },
  {
    id: 'smart-contract.signature.replay-missing-nonce',
    severityHint: 'high',
    claim: 'An `ecrecover`-based signature check is present with no visible nonce or deadline binding in the same window.',
    pattern: /ecrecover\s*\(/gi,
    suppressWindowPattern: /nonce|deadline|used\[|usedSignatures|EIP712|nonces\[/i,
    suppressScope: 'wide',
    hazards: ['A previously valid signature can be resubmitted (replayed) on-chain or across chains to re-trigger the authorized action.'],
    assumptions: ['Replay protection implemented via an external EIP-712 domain separator or a nonce contract not visible in this window is not detected and must be adjudicated.'],
    effectKind: 'principal-access', effectAction: 'replay-signature', effectScope: 'signature-check',
    chainRoles: ['starter', 'impact'],
  },
];

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `${rule.id}-observation`,
        semanticFeatures: ['smart-contract', rule.id, candidate.detectorMetadata?.file ?? rule.id],
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

export default Object.freeze({
  id: 'security.smart-contract',
  version: '1.0.0',
  candidateClass: 'smart-contract',
  description: 'Access control, reentrancy, oracle trust, upgradeability, and signature/replay handling in Solidity/Vyper source text.',
  supportTier: SUPPORT_TIER,
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      if (!/\.(sol|vy)$/i.test(file)) continue;
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      for (const rule of RULES) {
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(text)) !== null) {
          if (match[0].length === 0) { rule.pattern.lastIndex += 1; continue; }
          const radius = rule.suppressScope === 'wide' ? 600 : 250;
          if (rule.suppressWindowPattern && rule.suppressWindowPattern.test(windowAround(text, match.index, match[0].length, radius))) continue;
          if (rule.suppressPattern && rule.suppressPattern.test(match[0])) continue;

          observations.push({
            ruleId: rule.id,
            candidateClass: 'smart-contract',
            claim: rule.claim,
            severityHint: rule.severityHint,
            sources: [], sinks: artifact ? [artifact.id] : [],
            attackerCapabilities: ['submit-transaction', 'deploy-malicious-contract'],
            preconditions: [{
              kind: 'attacker-position', subject: 'actor:external', action: 'submit-transaction',
              scope: null, environment: 'blockchain', tenant: null,
            }],
            effects: [{
              kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
              object: artifact?.id ?? null, scope: rule.effectScope, environment: 'blockchain', tenant: null,
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
              'Lexical pattern match only; not confirmed by a fork simulation, static-analysis tool, or funded proof-of-concept.',
              'Reachability, attacker economic incentive, and value at risk must be adjudicated independently.',
            ],
          });
        }
      }
    }
    return observations;
  },
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
