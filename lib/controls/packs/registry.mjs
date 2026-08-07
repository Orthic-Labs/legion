import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { validatePack } from '../contracts.mjs';
export async function loadControlPacks(root) { const index = JSON.parse(await readFile(join(root, 'registry/controls/packs/index.json'), 'utf8')); return Promise.all(index.packs.map(async (path) => validatePack(JSON.parse(await readFile(join(root, path), 'utf8'))))); }
export function packIndex(packs) { const controls = new Map(); for (const pack of packs) for (const control of pack.controls) { const old = controls.get(control.id); if (old && JSON.stringify(old.evidence) !== JSON.stringify(control.evidence)) throw new Error(`incompatible duplicate control: ${control.id}`); controls.set(control.id, control); } return controls; }
