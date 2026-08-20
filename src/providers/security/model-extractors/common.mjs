// Security model entity/relation/fact constructors per Security Appendix
// §10.3. Deterministic IDs; assertions labeled observed vs assumed.

import { stableId } from '../contracts.mjs';

export function entity(kind, name, attributes, evidenceRefs, options = {}) {
  const body = {
    kind,
    name,
    attributes: attributes ?? {},
    assertion: options.assertion ?? 'observed',
    evidenceStrength: options.evidenceStrength ?? 'verified',
    evidenceRefs: [...new Set(evidenceRefs ?? [])].sort(),
  };
  return { ...body, id: stableId('security-model-entity', body) };
}

export function relation(kind, from, to, evidenceRefs, attributes = {}, options = {}) {
  const body = {
    kind,
    from,
    to,
    attributes,
    assertion: options.assertion ?? 'observed',
    evidenceStrength: options.evidenceStrength ?? 'verified',
    evidenceRefs: [...new Set(evidenceRefs ?? [])].sort(),
  };
  return { ...body, id: stableId('security-model-relation', body) };
}

export function fact(kind, fields, evidenceRefs = []) {
  const body = {
    kind,
    subject: fields.subject ?? null,
    action: fields.action ?? null,
    object: fields.object ?? null,
    scope: fields.scope ?? null,
    environment: fields.environment ?? null,
    tenant: fields.tenant ?? null,
    attributes: fields.attributes ?? {},
    evidenceRefs: [...new Set(evidenceRefs)].sort(),
  };
  return { ...body, id: stableId('security-fact', body) };
}

export function controlEntity(controlType, name, evidenceRefs, attributes = {}) {
  return entity('control', name, { controlType, ...attributes }, evidenceRefs);
}

// Common extractor per Security Appendix §11.1: repository artifacts from the
// Blueprint file list, package manifests and dependencies, deployment contexts,
// and external actors as explicit assumptions only.
export function extractCommon({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  for (const file of files ?? []) {
    const evidenceRef = stableId('artifact-evidence', { file });
    entities.push(entity('repository-artifact', file, { path: file }, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Repository artifact' });
  }

  const manifests = projection?.auditFacts?.packageManifests ?? [];
  for (const manifest of manifests) {
    const evidenceRef = stableId('manifest-evidence', { manifest });
    entities.push(entity('repository-artifact', `manifest ${manifest}`, { manifest: true }, [evidenceRef]));
    evidence.push({ id: evidenceRef, kind: 'source-location', file: String(manifest), description: 'Package manifest' });
  }

  return { entities, relations, evidence, initialFacts, coverageGaps };
}
