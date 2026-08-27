import { readFileSync } from 'node:fs';

// Canonical product version comes from release/version.json. Release tooling
// verifies every shipped manifest & native crate against this one value.
const releaseIdentity = JSON.parse(
  readFileSync(new URL('../../release/version.json', import.meta.url), 'utf8'),
);

export const LEGION_VERSION = releaseIdentity.version;
export const LEGION_PACKAGE = '@orthic-labs/legion';
export const LEGION_REPOSITORY = 'https://github.com/Orthic-Labs/legion';
