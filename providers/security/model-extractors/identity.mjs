// Identity extractor per Security Appendix §11.3: auth middleware/guards,
// role/permission checks, session/token creation, service accounts, OAuth/SAML
// callbacks, tenant identifiers, approval controls.

import { entity, fact, relation } from './common.mjs';
import { stableId } from '../contracts.mjs';

export function extractIdentity({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  for (const file of files) {
    const text = projection.sourceText?.[file] ?? '';
    if (!text) continue;
    if (/auth|session|jwt|oauth|saml|passport|getServerSession|login_required|requireAuth|middleware/.test(text)) {
      const evidenceRef = stableId('identity-evidence', { file });
      const control = entity('control', `auth control ${file}`, { controlType: 'authentication' }, [evidenceRef]);
      const principal = entity('principal', `authenticated principal ${file}`, { environment: 'application' }, [evidenceRef]);
      entities.push(control, principal);
      relations.push(relation('protected-by', stableId('identity-scope', { file }), control.id, [evidenceRef], {}, { assertion: 'observed' }));
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Identity control' });
    }
    if (/tenant|workspace|org_?id|company_id/.test(text)) {
      const evidenceRef = stableId('tenant-evidence', { file });
      const boundary = entity('trust-boundary', `tenant boundary ${file}`, { boundaryType: 'tenant' }, [evidenceRef]);
      entities.push(boundary);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Tenant boundary' });
    }
  }
  return { entities, relations, evidence, initialFacts, coverageGaps };
}
