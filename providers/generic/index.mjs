// Deterministic lexical fallback / generic source accounting. Provides
// inventory and lexical facts for every text language without claiming AST
// support. Unsupported parser never becomes silent omission.

export function lexicalAccounting({ files, parsedExtensions }) {
  const byExtension = new Map();
  for (const file of files ?? []) {
    const ext = file.split('.').pop()?.toLowerCase() ?? '';
    if (!byExtension.has(ext)) byExtension.set(ext, []);
    byExtension.get(ext).push(file);
  }
  const parsed = new Set((parsedExtensions ?? []).map((ext) => ext.toLowerCase()));
  const unsupported = [...byExtension.keys()]
    .filter((ext) => ext && !parsed.has(ext))
    .sort();
  return {
    schemaVersion: 1,
    kind: 'legion-lexical-accounting',
    fileCount: (files ?? []).length,
    parsedExtensions: [...parsed].sort(),
    unsupportedExtensions: unsupported,
    precisionTier: 'lexical', // never treated as AST/semantic evidence
    coverageGaps: unsupported.map((ext) => ({ kind: 'unsupported-extension', extension: ext })),
  };
}
