import { digest, sameBinding } from './binding.mjs';

export async function writeCanonicalManifest(store, binding) {
  const artifacts = store.records();
  const sourceRevision=binding?.sourceRevision??binding?.repositoryRevision??null;const terminalAbsences=artifacts.filter(({status})=>status==='missing').map(({path})=>path).sort();
  const value = { schemaVersion: 1, kind: 'legion-run-manifest', binding, sourceRevision, terminalAbsences, artifacts, digest: digest({ binding,sourceRevision,terminalAbsences, artifacts }) };
  await store.writeJson({ path: 'run-manifest.json', kind: 'run-manifest', producer: 'legion.core', producerVersion: '1.0.0', schemaVersion: 1, mediaType: 'application/json', binding, denominatorDigest: null, value });
  return value;
}

export function validateRunManifest(manifest, files, expectedBinding=manifest?.binding) {
  const issues=[];if(!manifest?.binding||!sameBinding(manifest.binding,expectedBinding))issues.push('binding:mismatch');if(!manifest?.sourceRevision)issues.push('source-revision:missing');
  const declared = new Map((manifest.artifacts ?? []).map((item) => [item.path, item.digest]));
  const actual = new Map((files ?? []).map((item) => [item.path, item.digest]));
  const absent=[...declared].filter(([path])=>!actual.has(path)).map(([path])=>path).sort();if(JSON.stringify(absent)!==JSON.stringify([...(manifest.terminalAbsences??[])].sort()))issues.push('terminal-absences:mismatch');
  return [...issues,...[...actual].filter(([path]) => !declared.has(path)).map(([path]) => `orphan:${path}`), ...[...declared].filter(([path, value]) => !actual.has(path) || actual.get(path) !== value).map(([path]) => `missing-or-drifted:${path}`)].sort();
}
