import { createHash } from 'node:crypto';

export function createWebQualificationFixtures({ binding = {} } = {}) {
  const receipt = (status, suffix, override = {}) => { const receiptBinding = override.binding ?? binding; const targetId = override.targetId ?? binding.targetId; const content = JSON.stringify({ family: 'web', suffix, targetId }); const artifact = { path: `raw/web/${suffix}.json`, family: 'web', digest: `sha256:${createHash('sha256').update(content).digest('hex')}`, binding: receiptBinding, content }; return { controlId: 'web-control', targetId, status, terminal: true, binding: receiptBinding, artifacts: [artifact], ...override }; };
  return [
    { id: 'clean', family: 'web', applicableControls: ['web-control'], receipts: [receipt('pass', 'clean')], rawArtifacts: ['raw/web/clean.json'] },
    { id: 'mitigated', family: 'web', applicableControls: ['web-control'], receipts: [receipt('partial', 'mitigated')], rawArtifacts: ['raw/web/mitigated.json'] },
    { id: 'missing', family: 'web', applicableControls: ['web-control'], receipts: [], rawArtifacts: ['raw/web/missing.json'] },
    { id: 'multi-target', family: 'web', applicableControls: ['web-control'], receipts: [receipt('pass', 'multi-target', { targetId: `${binding.targetId}-other`, binding: { ...binding, targetId: `${binding.targetId}-other` } })], rawArtifacts: ['raw/web/multi-target.json'] },
    { id: 'planted', family: 'web', applicableControls: ['web-control'], receipts: [receipt('fail', 'planted')], rawArtifacts: ['raw/web/planted.json'] },
    { id: 'stale', family: 'web', applicableControls: ['web-control'], receipts: [receipt('unproven', 'stale', { binding: { ...binding, sourceRevision: `${binding.sourceRevision}-stale` } })], rawArtifacts: ['raw/web/stale.json'] },
  ];
}
