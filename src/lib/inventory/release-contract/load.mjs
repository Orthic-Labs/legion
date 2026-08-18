import { readFile } from 'node:fs/promises';
import { mergeReleaseContract } from './merge.mjs';
export async function loadReleaseContract(path, inputs = {}) { const declared = path ? JSON.parse(await readFile(path, 'utf8')) : {}; if (declared.schemaVersion != null && declared.schemaVersion !== 1) throw new Error('unsupported release contract version'); return mergeReleaseContract({ ...inputs, declared }); }
