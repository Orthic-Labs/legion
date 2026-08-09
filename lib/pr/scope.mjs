// Changed-scope PR analysis per PR38. Base-aware introduced/fixed/existing
// classification; whole-repository coverage truth preserved separately. Never
// selects fewer providers merely because the UI is PR-shaped.

import { createHash } from 'node:crypto';

export function changedFiles({ mergeBase, head, committed, uncommitted, untracked }) {
  return {
    mergeBase,
    committed: [...(committed ?? [])].sort(),
    uncommitted: [...(uncommitted ?? [])].sort(),
    untracked: [...(untracked ?? [])].sort(),
  };
}

export function classifyFinding({ finding, changedPaths }) {
  const file = finding.file ? String(finding.file).replaceAll('\\', '/') : null;
  if (!file) return 'existing';
  const introduced = (changedPaths ?? []).some((path) => {
    const normalized = String(path).replaceAll('\\', '/').replace(/\/+$/, '');
    return file === normalized || file.startsWith(`${normalized}/`);
  });
  return introduced ? 'introduced' : 'existing';
}

export function prScopeResult({ findings, changedPaths, fullCoverage }) {
  const classified = (findings ?? []).map((finding) => ({
    ...finding,
    scope: classifyFinding({ finding, changedPaths }),
  }));
  return {
    schemaVersion: 1,
    kind: 'legion-pr-scope',
    introduced: classified.filter((f) => f.scope === 'introduced'),
    existing: classified.filter((f) => f.scope === 'existing'),
    // Whole-repository coverage truth is never dropped in PR mode.
    fullCoverage,
    providersNotRun: [],
    note: 'PR mode reports new blockers by default while preserving backlog visibility.',
  };
}

export function stableCommentId(finding) {
  return `sha256:${createHash('sha256').update(`pr-comment\0${finding.fingerprint ?? finding.id ?? finding.ruleId}`).digest('hex')}`;
}
