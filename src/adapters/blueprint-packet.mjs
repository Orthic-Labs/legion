/**
 * Membrane packet boundary for Blueprint repository evidence.
 *
 * Blueprint owns repository truth. This module only accepts a packet already
 * produced by Membrane's transport and exposes typed degradation when that
 * transport is unavailable. It never walks files, invokes Blueprint, or
 * derives repository facts locally.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { consumeMembranePacket } from '../packages/context/lib/context.mjs';

export function unavailablePacket(reason = 'membrane-transport-unavailable') {
  return { schema: 'legion.context-result.v1', status: 'unavailable', reason };
}

export function consumeBlueprintPacket(packet) {
  return consumeMembranePacket(packet);
}

export async function requestBlueprintPacket({ transport, request }) {
  if (typeof transport !== 'function') return unavailablePacket();
  try {
    return consumeBlueprintPacket(await transport({ operation: 'membrane_context', ...request }));
  } catch (error) {
    return unavailablePacket(error?.code === 'MEMBRANE_UNAVAILABLE' ? 'membrane-unavailable' : 'membrane-packet-invalid');
  }
}

/** Git binding is execution provenance, not repository semantic truth. */
export function collectRepositoryBinding(rootInput) {
  const root = resolve(rootInput);
  const git = (args, encoding = 'utf8') => {
    const result = spawnSync('git', args, { cwd: root, encoding, windowsHide: true, maxBuffer: 32 * 1024 * 1024 });
    if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed`);
    return result.stdout;
  };
  const revision = String(git(['rev-parse', 'HEAD'])).trim();
  const status = git(['status', '--porcelain=v1', '-z', '--untracked-files=normal'], 'buffer');
  const patch = git(['diff', '--binary', 'HEAD', '--'], 'buffer');
  const untracked = String(git(['ls-files', '--others', '--exclude-standard', '-z'])).split('\0').filter(Boolean).sort();
  const digest = createHash('sha256');
  digest.update('status\0'); digest.update(status); digest.update('patch\0'); digest.update(patch);
  for (const path of untracked) { digest.update('untracked\0'); digest.update(path); digest.update('\0'); digest.update(readFileSync(join(root, path))); }
  return { repositoryRevision: revision, dirty: status.length > 0, dirtyPatchDigest: `sha256:${digest.digest('hex')}` };
}

export function readBlueprintManifestBinding() {
  return { state: 'unproven', reason: 'membrane-blueprint-transport-unavailable' };
}

export function readBlueprintPacket() {
  return unavailablePacket('membrane-blueprint-transport-unavailable');
}
