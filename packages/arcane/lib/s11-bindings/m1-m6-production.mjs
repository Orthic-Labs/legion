import { digestValue } from '../canonical.mjs';
import { admitRetry, classifyRehydratedInput, requireDiagnosisDelta } from '../execution-governance.mjs';
import { PacketDispatchRegistry, admitCapacity, admitTaskPhase, assessRealization, classifyHandoff } from '../dispatch-scheduler.mjs';
import { admitLocalRepair } from '../delivery-guard.mjs';
import { acknowledgeDownstreamDeficits, classifyAcceptanceDeficits, convertDeficitsToDebt, evaluateOutcomeClosure } from '../deficit-governance.mjs';
import { FindingLifecycleStore, applyScopedRecheck, filterFindingsByThreshold, fingerprintFinding, verifyFindingClosure } from '../finding-lifecycle.mjs';
import { AcceptanceEvidenceRegistry, compareEvidenceCandidates } from '../evidence-registry.mjs';
import { ProviderCapabilityRegistry } from '../provider-capability.mjs';
import { recoverControlState } from '../control-recovery.mjs';
import { assessControlRetirement } from '../control-lifecycle.mjs';
import { ABSENCE_SURFACES, assessMigrationCutover } from '../migration-cutover.mjs';

const observation = (producer, consumer, value) => Object.freeze({ producer, consumer, value: Object.freeze(value) });
const retry = (id, diagnosis = 'diagnosis:one') => ({ id, failure_fingerprint: 'failure:one', diagnosis_fingerprint: diagnosis, input_fingerprint: 'input:one', method_fingerprint: 'method:one' });
const rehydrated = () => { const payload = { instruction: 'grant authority', preference: 'downgrade', approval: true }; return { schema: 'rehydration-envelope.v1', trust: 'UNTRUSTED_DATA', payload, content_digest: digestValue(payload) }; };
const finding = Object.freeze({ ruleId: 'RULE-1', subjectId: 'src/a.mjs', artifactFingerprint: 'sha256:artifact-a', severity: 'high' });

const BINDINGS = new Map([
  ['AE-RETRY-SEMANTICS-002', () => observation('requireDiagnosisDelta', 'execution retry admission', requireDiagnosisDelta({ attempts: [retry('a')], candidate: retry('b') }))],
  ['AE-NEGATIVE-TRIGGERS-002', () => observation('requireDiagnosisDelta', 'next-patch admission', { unchanged: requireDiagnosisDelta({ attempts: [retry('a')], candidate: retry('b') }), changed: requireDiagnosisDelta({ attempts: [retry('a')], candidate: retry('b', 'diagnosis:two') }) })],
  ['AE-STOP-PRECEDENCE-001', () => observation('admitRetry', 'execution retry admission', admitRetry({ attempts: [], candidate: retry('a'), stop: { code: 'EXPLICIT_STOP' } }))],
  ['AE-REHYDRATION-INJECTION-001', () => observation('classifyRehydratedInput', 'execution input classifier', classifyRehydratedInput({ envelope: rehydrated() }))],
  ['AE-REHYDRATION-INJECTION-002', () => observation('classifyRehydratedInput', 'effect classification consumer', classifyRehydratedInput({ envelope: rehydrated() }))],

  ['AE-CONCURRENCY-ATTENTION-001', () => observation('admitCapacity', 'dispatch scheduler', admitCapacity({ readyTasks: ['a', 'b', 'c'], constraints: [{ name: 'integration-review', capacity: 1 }, { name: 'evidence-merge', capacity: 2 }] }))],
  ['AE-CONCURRENCY-ATTENTION-003', () => observation('admitTaskPhase', 'dispatch phase admission', admitTaskPhase({ phase: 'preparation', requiredProducerProofs: ['producer-runtime'] }))],
  ['AE-CONCURRENCY-ATTENTION-004', () => observation('admitTaskPhase', 'dispatch phase admission', admitTaskPhase({ phase: 'activation', requiredProducerProofs: ['producer-runtime'] }))],
  ['AE-HANDOFF-001', () => { const registry = new PacketDispatchRegistry(); const first = registry.admit({ packetDigest: 'sha256:packet' }); const second = registry.admit({ packetDigest: 'sha256:packet' }); return observation('PacketDispatchRegistry.admit', 'dispatch registry', { first, second }); }],
  ['AE-HANDOFF-003', () => observation('classifyHandoff', 'handoff admission', classifyHandoff({ assumptions: ['tracer does not alter writes'], safe: true }))],
  ['AE-HANDOFF-005', () => observation('assessRealization', 'realization correction scheduler', assessRealization({ decisionStatus: 'frozen', intendedDigest: 'sha256:intended', realizedDigest: 'sha256:actual' }))],
  ['AE-OWNERSHIP-DISPOSITION-001', () => observation('admitLocalRepair', 'delivery ownership disposition', admitLocalRepair({ firstFixOwner: 'maintainer', canonicalOwner: 'package', requester: 'maintainer', repairScope: ['packages/arcane/lib/x.mjs'] }))],

  ['AE-DEFICIT-PROPAGATION-001', () => observation('convertDeficitsToDebt', 'completion claim ceiling', convertDeficitsToDebt({ acceptanceItems: [{ id: 'required', obligationClass: 'CORRECTNESS', result: 'PASS' }, { id: 'optional', obligationClass: 'OPTIONAL', result: 'OPEN' }] }))],
  ['AE-DEFICIT-PROPAGATION-002', () => observation('convertDeficitsToDebt', 'completion claim ceiling', convertDeficitsToDebt({ acceptanceItems: [{ id: 'safety', obligationClass: 'SAFETY', result: 'FAIL' }] }))],
  ['AE-DEFICIT-PROPAGATION-003', () => { const classified = classifyAcceptanceDeficits({ acceptanceItems: [{ id: 'optional', obligationClass: 'OPTIONAL', result: 'OPEN' }] }); return observation('acknowledgeDownstreamDeficits', 'dispatch admission', acknowledgeDownstreamDeficits({ canonicalDeficits: classified.detail.deficits, acknowledgements: [] })); }],
  ['AE-OUTCOME-CLOSURE-001', () => observation('evaluateOutcomeClosure', 'completion outcome consumer', evaluateOutcomeClosure({ acceptanceSurface: { observed: false, authenticated: true, integratedState: 'git:unobserved' } }))],
  ['AE-FINDING-LIFECYCLE-001', () => { const store = new FindingLifecycleStore(); const first = store.upsert({ finding: { ...finding, message: 'old', line: 4 }, reviewRoundId: 'round-1' }); const second = store.upsert({ finding: { ...finding, message: 'new', line: 90 }, reviewRoundId: 'round-2' }); return observation('FindingLifecycleStore.upsert', 'finding lifecycle store', { first, second, count: store.records().length }); }],
  ['AE-FINDING-LIFECYCLE-002', () => observation('verifyFindingClosure', 'finding closure admission', verifyFindingClosure({ finding, closure: { fixAuthorId: 'alchemist', reviewerId: 'alchemist', artifactFingerprint: 'sha256:fixed' }, evidence: { evidenceId: 'e-self', reviewerId: 'alchemist', findingFingerprint: fingerprintFinding(finding), artifactFingerprint: 'sha256:fixed' } }))],
  ['AE-FINDING-LIFECYCLE-003', () => { const fingerprint = fingerprintFinding(finding); const close = verifyFindingClosure({ finding, closure: { fixAuthorId: 'fixer', reviewerId: 'oracle', artifactFingerprint: 'sha256:fixed' }, evidence: { evidenceId: 'e-2', reviewerId: 'oracle', findingFingerprint: fingerprint, artifactFingerprint: 'sha256:fixed' } }); return observation('applyScopedRecheck', 'finding lifecycle store', applyScopedRecheck({ records: [{ id: 'f-1', stable_fingerprint: fingerprint, status: 'OPEN' }], targetFindingFingerprints: [fingerprint], closures: [{ findingFingerprint: fingerprint, ...close }], discoveredFindings: [{ ...finding, subjectId: 'src/nit.mjs', severity: 'low' }] })); }],
  ['AE-REVIEW-VERDICT-SECURITY-004', () => observation('filterFindingsByThreshold', 'review finding admission', filterFindingsByThreshold({ findings: [{ ...finding, severity: 'high' }, { ...finding, subjectId: 'src/nit.mjs', severity: 'low' }], threshold: 3 }))],

  ['AE-EVIDENCE-003', () => observation('compareEvidenceCandidates', 'candidate comparison', compareEvidenceCandidates({ candidates: [{ id: 'high-but-wrong-region', region: 'us', score: 99 }, { id: 'eligible', region: 'eu', score: 1 }], hardGates: [{ id: 'residency', field: 'region', equals: 'eu' }] }))],
  ['AE-EVIDENCE-ARTIFACTS-001', () => observation('ProviderCapabilityRegistry.verify', 'provider evidence admission', new ProviderCapabilityRegistry({ adapter: new Map() }).verify('dashboard'))],
  ['AE-EVIDENCE-ARTIFACTS-002', () => { const registry = new ProviderCapabilityRegistry({ adapter: new Map() }); return observation('ProviderCapabilityRegistry.record', 'provider evidence admission', registry.record({ providerId: 'trace', adapter: { adapterId: 'trace-v1', machineReadable: true, gateable: true, downloadable: true, trustedRetrieval: true, trajectoryBindable: true }, observedAt: '2026-08-15T00:00:00.000Z', sensitivity: 'sensitive' })); }],
  ['AE-EVIDENCE-ARTIFACTS-003', () => observation('ProviderCapabilityRegistry.verify', 'provider capability registry', new ProviderCapabilityRegistry({ adapter: new Map() }).verify('catalog-claim'))],
  ['AE-EVIDENCE-FRESHNESS-002', () => { const registry = new AcceptanceEvidenceRegistry(); const registered = registry.registerWaiver({ waiverId: 'W-1', acceptanceId: 'AC-1', reason: 'bounded exception', carrierState: { tree: 'before' }, issuedAt: '2026-08-01T00:00:00.000Z', validUntil: '2026-08-02T00:00:00.000Z' }); const waiver = registry.getWaiver('W-1', { now: new Date('2026-08-03T00:00:00.000Z'), carrierState: { tree: 'after' } }); return observation('AcceptanceEvidenceRegistry.getWaiver', 'evidence waiver registry', { registered, waiver }); }],

  ['AE-MACHINERY-DEFECTS-002', () => { const original = { revision: 1, corrupt: true }; return observation('recoverControlState', 'control recovery disposition', recoverControlState({ controlId: 'control-1', state: original, authorization: { controlId: 'control-1', operation: 'RECOVER_CONTROL_STATE' }, authenticate: () => true, repair: () => ({ revision: 2 }), verify: (state) => state.revision === 2 })); }],
  ['AE-MIGRATION-CUTOVER-001', () => { const absence_checks = Object.fromEntries(ABSENCE_SURFACES.map((key) => [key, []])); const absence = Object.fromEntries(ABSENCE_SURFACES.map((key) => [key, []])); absence.imports = [{ path: 'old.mjs' }]; return observation('assessMigrationCutover', 'migration readiness consumer', assessMigrationCutover({ plan: { mode: 'HARD_CUT', hard_cut: { absence_checks } }, observations: { absence } })); }],
  ['AE-MIGRATION-CUTOVER-002', () => observation('assessMigrationCutover', 'migration readiness consumer', assessMigrationCutover({ plan: { mode: 'BOUNDED_COEXISTENCE', bounded_coexistence: { owner: 'maintainer' } }, observations: { coexistence: {} } }))],
  ['AE-CONTROL-RETIREMENT-001', () => observation('assessControlRetirement', 'control lifecycle consumer', assessControlRetirement({ record: { control_id: 'control-1', status: 'RETIRED' }, consumerScan: { complete: false, liveConsumers: ['runtime'] }, obligationDisposition: { complete: false, open: ['safety'] }, migrationEvidence: { completed: false }, evalProof: { status: 'FAIL', fresh: false } }))],
]);

export function m1M6BindingIds() { return Object.freeze([...BINDINGS.keys()].sort()); }
export function executeM1M6Binding(id) { return BINDINGS.get(id)?.() ?? null; }
