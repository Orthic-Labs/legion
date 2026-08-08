import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createWebQualificationFixtures } from '../qualification/platforms/web/fixtures.mjs';
import { qualifyWebPlatform } from '../qualification/platforms/web/qualification.mjs';

export async function qualifyWebPlatformFile(path) {
  const input = JSON.parse(await readFile(path, 'utf8'));
  return qualifyWebPlatform({ binding: input.binding, fixtures: input.fixtures ?? createWebQualificationFixtures({ binding: input.binding }) });
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  if (!process.argv[2]) throw new Error('usage: node scripts/qualify-web-platform.mjs <input.json>');
  process.stdout.write(`${JSON.stringify(await qualifyWebPlatformFile(process.argv[2]))}\n`);
}
