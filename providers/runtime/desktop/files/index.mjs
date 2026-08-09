const TERMINAL = new Set(['pass', 'fail', 'partial', 'unproven', 'blocked', 'error']);
export const FILE_CASES = Object.freeze(['empty', 'zero-byte', 'large', 'malformed', 'unsupported', 'duplicate', 'read-only', 'network', 'cloud-synced', 'externally-changed', 'externally-deleted', 'long-path', 'unicode-rtl', 'symlink', 'archive-bomb', 'permission-boundary', 'atomic-save', 'cancellation', 'disk-full', 'temp-cleanup', 'corruption', 'backup-restore', 'os-user-isolation', 'cloud-conflict', 'deep-link', 'clipboard', 'drag-drop', 'open-save-dialog', 'file-association']);

export function evaluateDesktopStorage({ cases = [], migrations = [], locations = {}, evidence = {} } = {}) {
  const receipts = [...cases, ...migrations];
  const gaps = [];
  for (const item of receipts) {
    if (!item.id || item.terminal !== true || !TERMINAL.has(item.status)) gaps.push(`scenario-unproven:${item.id ?? 'unknown'}`);
  }
  for (const migration of migrations) if (migration.status !== 'pass' && migration.sourcePreserved !== true) gaps.push(`migration-source-not-preserved:${migration.id ?? 'unknown'}`);
  const locationValues = ['data', 'cache', 'logs', 'temp'].map((key) => locations[key]).filter(Boolean);
  if (locationValues.length !== 4) gaps.push('storage-locations-incomplete');
  else if (new Set(locationValues).size !== 4) gaps.push('storage-locations-not-separated');
  for (const id of FILE_CASES) if (!cases.some((item) => item.id === id && item.terminal === true)) gaps.push(`file-case-missing:${id}`);
  if (!migrations.length) gaps.push('migration-denominator-empty');
  if (evidence.source !== 'native-host' || evidence.terminal !== true) gaps.push('native-storage-receipt-missing');
  const status = gaps.some((gap) => gap.startsWith('migration-source-not-preserved')) ? 'fail' : gaps.length ? 'unproven' : 'pass';
  return { schemaVersion: 1, kind: 'legion-desktop-files-storage', status, terminal: true, locations, receipts, evidence,
    denominator: { total: receipts.length, accounted: receipts.filter((item) => item.id && item.terminal === true && TERMINAL.has(item.status)).length }, coverageGaps: gaps.sort() };
}

export async function executeDesktopStorage({ host, migrationIds = [] } = {}) {
  if (!host?.run || !host?.locations) return evaluateDesktopStorage({});
  const cases = [];
  for (const id of FILE_CASES) cases.push(await host.run({ id, kind: 'file-storage' }));
  const migrations = [];
  for (const id of migrationIds) migrations.push(await host.run({ id, kind: 'migration' }));
  const evidence = typeof host.receipt === 'function' ? await host.receipt() : {};
  return evaluateDesktopStorage({ cases, migrations, locations: await host.locations(), evidence });
}
