import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createMobileQualificationFixtures } from '../qualification/platforms/mobile/fixtures.mjs';
import { qualifyMobilePlatform } from '../qualification/platforms/mobile/qualification.mjs';

export async function qualifyMobilePlatformFile(path) {
  const input = JSON.parse(await readFile(path, 'utf8'));
  return qualifyMobilePlatform({ ...input, fixtures: input.fixtures ?? createMobileQualificationFixtures() });
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  if (!process.argv[2]) throw new Error('usage: node scripts/qualify-mobile-platform.mjs <input.json>');
  process.stdout.write(`${JSON.stringify(await qualifyMobilePlatformFile(process.argv[2]))}\n`);
}
