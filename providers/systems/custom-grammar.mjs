// Trusted custom grammar records per SNIP-CUSTOM-GRAMMAR-01. Custom grammars
// load only from trusted host configuration with a pinned digest and sandboxed
// parser host. Repository config may reference an ID but cannot introduce a
// path or digest.

import { createHash } from 'node:crypto';

export function customGrammarRecord({ languageId, grammarPath, grammarDigest, source = 'host-config', abi = 'tree-sitter' }) {
  if (source !== 'host-config') throw new Error(`custom grammar source must be host-config; got ${source}`);
  return {
    schemaVersion: 1,
    kind: 'nemesis-custom-grammar',
    languageId,
    grammarPath,
    grammarDigest,
    source,
    abi,
    qualified: false,
    qualificationArtifact: null,
  };
}

export function stableGrammarId(languageId, grammarDigest) {
  return `sha256:${createHash('sha256').update(`custom-grammar\0${languageId}\0${grammarDigest}`).digest('hex')}`;
}

export function rejectRepositoryGrammar(repositoryConfig) {
  // Repository config may only reference a grammar ID, never supply path/digest.
  if (repositoryConfig?.grammarPath || repositoryConfig?.grammarDigest) {
    throw new Error('repository config may not introduce custom grammar path or digest');
  }
  return true;
}
