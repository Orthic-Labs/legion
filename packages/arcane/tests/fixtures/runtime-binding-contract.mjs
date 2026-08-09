import { join } from 'node:path';
import { ContractSealStore } from '../../lib/contract-seal-store.mjs';
import { digestValue } from '../../lib/canonical.mjs';

export const EC5_DIGEST = 'sha256:581fbaa5d6a1f6fd251ddf25c83d41f0bcad9ac5394b5563871a55ea6edbd15c';
export const EC6_DIGEST = 'sha256:0b214b71f686884eb57639eae0f092affc162ad7d186e6e85e5895fd72e5771e';
export const assertion = { authority: 'sage', assertedBy: 'host', verificationMethod: 'capability-signature', perMessage: true };
export const b5Contract = (contractId = 'EC-5') => ({ schemaVersion: 1, kind: 'legion-execution-contract', contractId, version: 1, sourceRevision: 'abcdef0', objective: 'x', currentState: 'x', desiredState: 'x', requirements: [], decisions: [], invariants: [], nonGoals: [], scope: { own: [], read: [], forbidden: [] }, artifacts: { exact: [{ id: 'a', path: 'x', latitude: 'EXACT', content: 'x' }], bounded: [{ id: 'b', path: 'y', latitude: 'BOUNDED', locked: ['x'], freedom: ['y'] }] }, tasks: ['T-1'], dependencies: [], acceptanceCriteria: [], declaredChecks: [], evidenceRequirements: [], authorizedEffectClasses: [], repairLatitude: [], stopConditions: [], escalationConditions: [], rollback: [], openQuestions: [] });
export function seedStore(root, contract = b5Contract()) { const store = new ContractSealStore({ root: join(root, 'contract-seals'), clock: () => '2026-08-09T12:00:00.000Z' }); const result = store.seal({ contract, authorityAssertion: assertion }); return { store, record: result.record, digest: digestValue(contract) }; }
