// Packaged-skill verification.
//
// Legion is the canonical source for the skills it ships. There is no upstream to diff against, so
// a packaged file is verified against one digest and the manifest that declares it -- not against a
// transform of some other copy living elsewhere.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { digestBytes } from '../artifacts/digests.mjs';

const PACKAGE_URI = /legion-skill:\/\/[a-z0-9-]+\/[^\s)`"']+/g;

export function verifySkillBytes(bytes, expectedDigest) {
  const digest = digestBytes(Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes));
  return { ok: digest === expectedDigest, digest, expectedDigest };
}

export function verifySkillCatalog({ packageRoot, manifests, publication = false }) {
  const findings = [];
  const declaredUris = new Set(Object.values(manifests).flatMap((manifest) => (manifest.files ?? []).map(({ uri }) => uri)));
  for (const manifest of Object.values(manifests)) {
    const declared = new Set();
    if (publication && manifest.licenseState === 'unresolved') {
      findings.push(finding('rights-unresolved', manifest.id, null, 'publication rejects unresolved rights'));
    }
    for (const record of manifest.files ?? []) {
      const outputPath = safePath(packageRoot, join('skills', manifest.id, record.path));
      if (!outputPath) {
        findings.push(finding('invalid-path', manifest.id, record.path, 'output path escapes package root'));
        continue;
      }
      declared.add(outputPath);
      verifyFile(manifest, record, outputPath, declaredUris, findings);
    }
    findUnexpected(packageRoot, manifest.id, declared, findings);
  }
  return { ok: findings.length === 0, findings };
}

function verifyFile(manifest, record, outputPath, declaredUris, findings) {
  if (!existsSync(outputPath)) {
    findings.push(finding('missing', manifest.id, record.path, 'declared file is missing'));
    return;
  }
  const bytes = readFileSync(outputPath);
  const verification = verifySkillBytes(bytes, record.digest);
  if (!verification.ok) {
    findings.push(finding('digest-drift', manifest.id, record.path, 'file digest differs from manifest', verification));
  }
  if (!/(?:^|\.)(?:md|mdx|txt)$/i.test(record.path)) return;
  for (const match of bytes.toString('utf8').matchAll(PACKAGE_URI)) {
    const uri = match[0].split('#', 1)[0];
    if (!declaredUris.has(uri)) {
      findings.push(finding('broken-link', manifest.id, record.path, `packaged link is not declared: ${uri}`));
    }
  }
}

function findUnexpected(packageRoot, bundleId, declared, findings) {
  const bundleRoot = resolve(packageRoot, 'skills', bundleId);
  if (!existsSync(bundleRoot)) return;
  for (const path of allFiles(bundleRoot)) {
    if (!declared.has(path)) {
      findings.push(finding('unexpected', bundleId, relative(bundleRoot, path).replaceAll('\\', '/'), 'file is absent from manifest'));
    }
  }
}

function allFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? allFiles(path) : [path];
  });
}

function safePath(root, path) {
  const base = resolve(root), target = resolve(base, path);
  return target.startsWith(`${base}${sep}`) ? target : null;
}

function finding(code, bundleId, path, detail, digests = null) {
  return {
    code, bundleId, path, detail,
    ...(digests ? { expectedDigest: digests.expectedDigest, actualDigest: digests.digest } : {}),
  };
}
