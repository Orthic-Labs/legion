import { digest } from './binding.mjs';

export async function writeCanonicalManifest(store, binding) {
  const artifacts = store.records();
  const value = { schemaVersion: 1, kind: 'nemesis-run-manifest', binding, artifacts, digest: digest({ binding, artifacts }) };
  await store.writeJson({ path: 'run-manifest.json', kind: 'run-manifest', producer: 'nemesis.core', producerVersion: '1.0.0', schemaVersion: 1, mediaType: 'application/json', binding, denominatorDigest: null, value });
  return value;
}
