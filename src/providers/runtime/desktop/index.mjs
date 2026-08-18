const account = (expected, actual) => {
  const ids = [...new Set(expected)].sort();
  const present = new Set(actual);
  const missing = ids.filter((id) => !present.has(id));
  return { total: ids.length, accounted: ids.length - missing.length, missing };
};

export const REQUIRED_EVIDENCE_FAMILIES = Object.freeze(['process', 'ipc', 'files', 'storage', 'os', 'performance', 'installer', 'updater', 'platform']);
const familiesFor = (receipt) => {
  if (Array.isArray(receipt.evidenceFamilies)) return receipt.evidenceFamilies;
  if (receipt.evidenceFamily) return [receipt.evidenceFamily];
  return {
    'legion-desktop-runtime': ['process'],
    'legion-desktop-ipc': ['ipc'],
    'legion-desktop-files-storage': ['files', 'storage'],
    'legion-desktop-os-matrix': ['os'],
    'legion-desktop-performance': ['performance'],
    'legion-desktop-installer-lifecycle': ['installer'],
    'legion-desktop-updater': ['updater'],
    'legion-desktop-windows': ['platform'],
    'legion-desktop-macos': ['platform'],
    'legion-desktop-linux': ['platform'],
  }[receipt.kind] ?? [];
};

export function integrateDesktopEvidence({ targetId, controls = [], scenarios = [], receipts = [], platformMatrices = [] } = {}) {
  const gaps = [];
  const admitted = [];
  for (const receipt of receipts) {
    if (receipt.targetId !== targetId) { gaps.push(`target-binding-mismatch:${receipt.controlId ?? receipt.scenarioId ?? 'unknown'}`); continue; }
    if (receipt.terminal !== true) { gaps.push(`receipt-nonterminal:${receipt.controlId ?? receipt.scenarioId ?? 'unknown'}`); continue; }
    if (receipt.sourceRegexOnly === true || receipt.claimLevel === 'source' && /release/i.test(receipt.controlId ?? '')) gaps.push(`native-release-evidence-missing:${receipt.controlId}`);
    admitted.push(receipt);
  }
  const closureReceipts = admitted.filter((item) => !(item.sourceRegexOnly === true || item.claimLevel === 'source' && /release/i.test(item.controlId ?? '')));
  const controlCounts = account(controls, closureReceipts.map((item) => item.controlId).filter(Boolean));
  const scenarioCounts = account(scenarios, closureReceipts.map((item) => item.scenarioId).filter(Boolean));
  const presentFamilies = new Set(admitted.flatMap(familiesFor));
  const evidenceFamilies = account(REQUIRED_EVIDENCE_FAMILIES, [...presentFamilies]);
  gaps.push(...controlCounts.missing.map((id) => `control-missing:${id}`), ...scenarioCounts.missing.map((id) => `scenario-missing:${id}`));
  gaps.push(...evidenceFamilies.missing.map((id) => `evidence-family-missing:${id}`));
  for (const matrix of platformMatrices) if (!matrix.os || !['pass', 'unsupported', 'unproven', 'partial', 'fail'].includes(matrix.status)) gaps.push(`platform-matrix-invalid:${matrix.os ?? 'unknown'}`);
  const stopShip = gaps.some((gap) => /nonterminal|binding-mismatch|native-release/.test(gap)) || admitted.some((item) => ['fail', 'error', 'blocked'].includes(item.status));
  return { schemaVersion: 1, kind: 'legion-desktop-platform-pack', status: stopShip ? 'fail' : gaps.length ? 'partial' : 'pass', terminal: true, provisional: true, stopShip, incomplete: gaps.length > 0, targetId,
    denominator: { controls: controlCounts, scenarios: scenarioCounts, evidenceFamilies }, receipts: admitted, platformMatrices, coverageGaps: [...new Set(gaps)].sort() };
}
