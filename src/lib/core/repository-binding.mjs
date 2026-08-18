import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, resolve } from 'node:path';
import { digest } from './binding.mjs';

async function files(root, current = root, output = []) {
  for (const entry of await readdir(current, { withFileTypes: true })) {
    if (['.git', 'node_modules', '.legion'].includes(entry.name)) continue;
    const path = join(current, entry.name);
    if (entry.isDirectory()) await files(root, path, output);
    else if (entry.isFile()) output.push(relative(root, path).replaceAll('\\', '/'));
  }
  return output;
}

export async function bindRepository(root, { revision = null, sourceRevision = revision, cortexDigest = null, skillRegistryDigest = null, familyRegistryDigest = null, providerRegistryDigest = null, configDigest = null } = {}) {
  const absoluteRoot = resolve(root);
  const names = (await files(absoluteRoot)).sort();
  const hash = createHash('sha256');
  for (const name of names) {
    const path = join(absoluteRoot, name);
    hash.update(`${name}\0`); hash.update(await readFile(path));
  }
  const dirtyOverlayDigest=`sha256:${hash.digest('hex')}`;const authorities={cortexDigest,skillRegistryDigest,familyRegistryDigest,providerRegistryDigest,configDigest};
  return Object.freeze({ schemaVersion: 1, root: absoluteRoot, repositoryRevision: revision,sourceRevision,dirtyOverlayDigest,fileCount:names.length,...authorities,digest:digest({revision,sourceRevision,dirtyOverlayDigest,names,authorities}) });
}
