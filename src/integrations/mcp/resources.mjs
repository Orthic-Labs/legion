import { readFileSync } from 'node:fs';
import { resolve, relative, sep } from 'node:path';

export function listResources() {
  return [{ uri: 'legion://run/report', name: 'Legion canonical report', mimeType: 'application/json' }];
}

export function readResource({ uri, run }, { root = process.cwd(), maxBytes = 1_000_000 } = {}) {
  if (uri !== 'legion://run/report') throw new Error(`unknown resource: ${uri}`);
  const base = resolve(root);
  const path = resolve(base, run ?? '', 'report.json');
  const rel = relative(base, path);
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`)) throw new Error('resource path escapes host root');
  const text = readFileSync(path, 'utf8');
  if (Buffer.byteLength(text) > maxBytes) throw new Error('resource exceeds configured limit');
  return { contents: [{ uri, mimeType: 'application/json', text }] };
}
