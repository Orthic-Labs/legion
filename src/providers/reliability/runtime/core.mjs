export function assessRuntimeReliability(receipts = []) {
  const failed = receipts.filter((receipt) => receipt.status !== 'pass');
  return { schemaVersion: 1, provider: 'reliability.runtime', status: failed.some((receipt) => receipt.status === 'fail') ? 'fail' : failed.length ? 'unproven' : 'pass', complete: failed.length === 0, receipts, coverageGaps: failed.map((receipt) => receipt.reason ?? `runtime-receipt:${receipt.id ?? 'unknown'}`) };
}
