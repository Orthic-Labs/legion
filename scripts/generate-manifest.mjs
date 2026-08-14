#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalJson, loadProviderRegistry, renderManifest } from '../registry/provider-registry.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const AUDIT_ROOT = resolve(HERE, '..');

export function generatedManifestText(registryPath = resolve(AUDIT_ROOT, 'registry/providers.json')) {
  return `${JSON.stringify(renderManifest(loadProviderRegistry(registryPath)), null, 2)}\n`;
}

function compatibleCheckedInManifest(actual, expected) {
  const errors = [];
  if (actual?.discovery_owner !== expected.discovery_owner) errors.push('discovery_owner');
  if (actual?.concurrency !== expected.concurrency) errors.push('concurrency');
  if (canonicalJson(actual?.checks ?? []) !== canonicalJson(expected.checks ?? [])) errors.push('checks');
  if (Array.isArray(actual?.providers)) {
    if (canonicalJson(actual.providers) !== canonicalJson(expected.providers)) errors.push('providers');
  }
  return { valid: errors.length === 0, errors, providerMirrorPresent: Array.isArray(actual?.providers) };
}

async function main() {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const registryIndex = args.indexOf('--registry');
  const outIndex = args.indexOf('--out');
  const registryPath = registryIndex >= 0 ? resolve(args[registryIndex + 1]) : resolve(AUDIT_ROOT, 'registry/providers.json');
  const outPath = outIndex >= 0 ? resolve(args[outIndex + 1]) : resolve(AUDIT_ROOT, 'manifest.json');
  const expectedText = generatedManifestText(registryPath);
  const expected = JSON.parse(expectedText);
  if (check) {
    let actual = null;
    try { actual = JSON.parse(readFileSync(outPath, 'utf8')); } catch {}
    const compatibility = compatibleCheckedInManifest(actual, expected);
    if (!compatibility.valid) {
      console.error(`manifest drift (${compatibility.errors.join(', ')}): regenerate ${outPath} from the executed provider registry`);
      process.exit(1);
    }
    if (!compatibility.providerMirrorPresent) {
      console.log(`manifest scanner checks match; complete provider contracts are validated directly from registry data. Regeneration will add the provider mirror: ${outPath}`);
    } else {
      console.log(`manifest matches complete executed provider registry: ${outPath}`);
    }
    return;
  }
  writeFileSync(outPath, expectedText, 'utf8');
  console.log(outPath);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.stack ?? error.message);
    process.exit(1);
  });
}
