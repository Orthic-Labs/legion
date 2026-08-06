// Cloud extractor per Security Appendix §11.6: Terraform/Kubernetes/cloud
// config — public entrypoints, IAM principals/policies/actions/resources,
// role-assumption relations, storage, workload identities.

import { entity, relation } from './common.mjs';
import { stableId } from '../contracts.mjs';

export function extractCloud({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  for (const file of files) {
    if (!/\.(tf|yaml|yml|json)$/.test(file)) continue;
    const text = projection.sourceText?.[file] ?? '';
    if (!text) continue;
    if (/0\.0\.0\.0\/0|ingress|public/.test(text)) {
      const evidenceRef = stableId('cloud-public-evidence', { file });
      const entrypoint = entity('entrypoint', `public cloud entrypoint ${file}`, { environment: 'cloud' }, [evidenceRef]);
      entities.push(entrypoint);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Public cloud entrypoint' });
    }
    if (/\b(?:iam|role|policy|principal|assume_role|serviceAccount)\b/.test(text)) {
      const evidenceRef = stableId('cloud-iam-evidence', { file });
      const principal = entity('principal', `IAM principal ${file}`, { environment: 'cloud' }, [evidenceRef]);
      const role = entity('identity', `IAM role ${file}`, { environment: 'cloud' }, [evidenceRef]);
      entities.push(principal, role);
      relations.push(relation('authenticates-as', principal.id, role.id, [evidenceRef]));
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'IAM principal/role' });
    }
    if (/\b(?:s3|bucket|storage|blob)\b/.test(text)) {
      const evidenceRef = stableId('cloud-storage-evidence', { file });
      const storage = entity('asset', `storage ${file}`, { assetKind: 'storage' }, [evidenceRef]);
      entities.push(storage);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Storage asset' });
    }
  }
  return { entities, relations, evidence, initialFacts, coverageGaps };
}
