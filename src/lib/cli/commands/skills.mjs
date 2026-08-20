import { validateSkillBundle } from '../../skills/contracts.mjs';
import { verifySkillCatalog } from '../../skills/verify.mjs';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { validateCommercialLenses } from '../../lenses/routing.mjs';
import { validateInternalRecipes } from '../../recipes/validate.mjs';
const packageRoot = fileURLToPath(new URL('../../../../', import.meta.url));
async function packagedManifests() { const index = JSON.parse(await readFile(new URL('../../../../src/registry/skills/index.json', import.meta.url), 'utf8')); return Object.fromEntries(await Promise.all(index.bundles.map(async ({ id, manifest }) => [id, JSON.parse(await readFile(new URL(`../../../../${manifest}`, import.meta.url), 'utf8'))]))); }
export async function runSkills(argv, { stdout, stderr }, manifests = null) {
  manifests ??= await packagedManifests(); if (argv.includes('--help')) { stdout.write('Usage: legion skills [list|verify] [--bundle <id>] [--publication]\n'); return { exitCode: 0 }; }
  const command = argv[0] ?? 'list'; let publication = false; const bundles = [];
  for (let index = 1; index < argv.length; index++) { if (argv[index] === '--bundle' && argv[index + 1]) bundles.push(argv[++index]); else if (argv[index] === '--publication') publication = true; else { stderr.write(`unknown option: ${argv[index]}\n`); return { exitCode: 4 }; } }
  const unknown = bundles.find((bundle) => !manifests[bundle]); if (unknown) { stderr.write(`unknown skill bundle: ${unknown}\n`); return { exitCode: 4 }; }
  const selected = bundles.length ? Object.fromEntries(bundles.map((bundle) => [bundle, manifests[bundle]])) : manifests;
  if (command === 'list') { stdout.write(`${JSON.stringify({ skills: Object.keys(selected).sort() })}\n`); return { exitCode: 0 }; }
  if (command === 'verify') { for (const manifest of Object.values(selected)) validateSkillBundle(manifest); const skills = verifySkillCatalog({ packageRoot, manifests: selected, publication }); const supporting = bundles.length ? [] : [...validateCommercialLenses(packageRoot).findings, ...validateInternalRecipes(packageRoot).findings]; const findings = [...skills.findings, ...supporting]; stdout.write(`${JSON.stringify({ status: findings.length ? 'fail' : 'pass', count: Object.keys(selected).length, findings })}\n`); return { exitCode: findings.length ? 5 : 0 }; }
  stderr.write(`unknown skills command: ${command}\n`); return { exitCode: 4 };
}
