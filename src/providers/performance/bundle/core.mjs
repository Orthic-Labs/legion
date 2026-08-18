export function analyzeBundleEvidence({ artifact = null, modules = [] } = {}) {
  if (!artifact?.id || !artifact?.digest) return { provider: 'performance.bundle', status: 'unproven', artifact, candidates: [], coverageGaps: ['build-artifact-identity-missing'] };
  const candidates = [];
  for (const module of modules) {
    if (module.duplicate) candidates.push({ ruleId: 'performance.bundle-duplicate-module', module: module.name, bytes: module.bytes, artifactId: artifact.id });
    if (module.dead) candidates.push({ ruleId: 'performance.bundle-dead-dependency', module: module.name, bytes: module.bytes, artifactId: artifact.id });
    if (module.renderBlocking) candidates.push({ ruleId: 'performance.bundle-render-blocking', module: module.name, bytes: module.bytes, artifactId: artifact.id });
    if (module.heavyLibrary) candidates.push({ ruleId: 'performance.bundle-heavy-library', module: module.name, bytes: module.bytes, artifactId: artifact.id });
    if (module.codeSplitMissing) candidates.push({ ruleId: 'performance.bundle-code-split', module: module.name, bytes: module.bytes, artifactId: artifact.id });
  }
  return { provider: 'performance.bundle', status: candidates.length ? 'candidates' : 'pass', artifact, candidates, coverageGaps: [] };
}
