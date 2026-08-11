import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { digestBytes } from '../artifacts/digests.mjs';
import { transformSkillText } from './transform.mjs';

export function verifySkillBytes(bytes, expectedDigest) {
  const digest = digestBytes(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
  return { ok: digest === expectedDigest, digest, expectedDigest };
}

export function verifySkillCatalog({ packageRoot, manifests, sourceRoot = null, publication = false }) {
  const findings = [];
  for (const manifest of Object.values(manifests)) {
    const declared = new Set();
    if (publication && manifest.licenseState === 'unresolved') findings.push(finding('rights-unresolved', manifest.id, null, 'publication rejects unresolved rights'));
    for (const record of manifest.files ?? []) {
      const outputPath = safePath(packageRoot, join('skills', manifest.id, record.path));
      if (!outputPath) { findings.push(finding('invalid-path', manifest.id, record.path, 'output path escapes package root')); continue; }
      declared.add(outputPath);
      verifyOutput(manifest, record, outputPath, findings);
      if (sourceRoot) verifySource(manifest, record, sourceRoot, outputPath, findings);
    }
    findUnexpected(packageRoot, manifest.id, declared, findings);
  }
  return { ok: findings.length === 0, findings };
}

function verifyOutput(manifest, record, outputPath, findings) {
  if (!existsSync(outputPath)) { findings.push(finding('missing', manifest.id, record.path, 'declared output is missing')); return; }
  const verification = verifySkillBytes(readFileSync(outputPath), record.outputDigest);
  if (!verification.ok) findings.push(finding('digest-drift', manifest.id, record.path, 'output digest differs from manifest', verification));
}

function verifySource(manifest, record, sourceRoot, outputPath, findings) {
  const sourcePath = safePath(sourceRoot, join(manifest.id, record.path));
  if (!sourcePath || !existsSync(sourcePath)) { findings.push(finding('missing', manifest.id, record.path, 'canonical source is missing')); return; }
  const source = readFileSync(sourcePath);
  const sourceVerification = verifySkillBytes(source, record.sourceDigest);
  if (!sourceVerification.ok) findings.push(finding('digest-drift', manifest.id, record.path, 'source digest differs from manifest', sourceVerification));
  const transformed = Buffer.from(transformSkillText(source.toString('utf8'), { bundle: manifest.id, path: record.path, profile: 'audit' }));
  if (!existsSync(outputPath) || !transformed.equals(readFileSync(outputPath))) findings.push(finding('transform-drift', manifest.id, record.path, 'canonical source transform differs from output'));
}

function findUnexpected(packageRoot, bundleId, declared, findings) { const bundleRoot = resolve(packageRoot, 'skills', bundleId); if (!existsSync(bundleRoot)) return; for (const path of allFiles(bundleRoot)) if (!declared.has(path)) findings.push(finding('unexpected', bundleId, relative(bundleRoot, path).replaceAll('\\', '/'), 'output is absent from manifest')); }
function allFiles(directory) { return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => { const path = join(directory, entry.name); return entry.isDirectory() ? allFiles(path) : [path]; }); }
function safePath(root, path) { const base = resolve(root); const target = resolve(base, path); return target.startsWith(`${base}${sep}`) ? target : null; }
function finding(code, bundleId, path, detail, digests = null) { return { code, bundleId, path, detail, ...(digests ? { expectedDigest: digests.expectedDigest, actualDigest: digests.digest } : {}) }; }
