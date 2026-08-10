// Reads Legion's own doctrine/ directory at runtime (never reaches back into
// D:/workspace or any other external path — doctrine/ is this package's local,
// byte-for-byte copy of the source-of-truth doctrine files).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

const DOCTRINE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'doctrine');

export function doctrineText(name) {
  return readFileSync(resolve(DOCTRINE_DIR, name), 'utf8');
}

export const DOCTRINE_PATHS = Object.freeze({
  legion: resolve(DOCTRINE_DIR, 'legion.md'),
  sage: resolve(DOCTRINE_DIR, 'sage.md'),
  alchemist: resolve(DOCTRINE_DIR, 'alchemist.md'),
  oracle: resolve(DOCTRINE_DIR, 'oracle.md'),
  covenantSeat: resolve(DOCTRINE_DIR, 'covenant-seat.md'),
});
