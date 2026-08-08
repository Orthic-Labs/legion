import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createDesktopQualificationFixtures } from '../qualification/platforms/desktop/fixtures.mjs';
import { qualifyDesktopPlatform } from '../qualification/platforms/desktop/qualification.mjs';
import { integrateDesktopEvidence } from '../providers/runtime/desktop/index.mjs';

export async function qualifyDesktopPlatformFile(path) {
  const input = JSON.parse(await readFile(path, 'utf8'));
  const qualification = qualifyDesktopPlatform({ targetId: input.targetId, fixtures: input.fixtures ?? createDesktopQualificationFixtures({ targetId: input.targetId }) });
  const pack = integrateDesktopEvidence({ targetId: input.targetId, controls: input.controls ?? [], scenarios: input.scenarios ?? [], receipts: input.receipts ?? [], platformMatrices: input.platformMatrices ?? [] });
  return { schemaVersion: 1, kind: 'nemesis-desktop-provisional-bundle', status: pack.stopShip ? 'fail' : qualification.status === 'pass' && pack.status === 'pass' ? 'pass' : 'partial', terminal: true, provisional: true, qualification, pack };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  if (!process.argv[2]) throw new Error('usage: node scripts/qualify-desktop-platform.mjs <input.json>');
  process.stdout.write(`${JSON.stringify(await qualifyDesktopPlatformFile(process.argv[2]))}\n`);
}
