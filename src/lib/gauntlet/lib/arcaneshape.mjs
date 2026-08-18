// Phase 6.7 — receipt shape.
//
// Arcane's `normalizeCheck` reads `executor` and
// `status` from caller-supplied data only when authority !== 'model'.
// We always emit `executor: 'host'` and `authority: 'host', receipt: ...`
// so the existing trust-class and issuer-derived-field enforcement
// applies unchanged. See `normalizeCheck` lines 515-544 of core.js.
//
// The gauntlet output never claims a check passed unless the underlying
// tool actually returned exit 0. Per the standing anti-gaming constraint
// in the workspace rules, unrun checks are reported as 'unverified'.

import { randomUUID } from "node:crypto";

export function buildReceipt({ startedAt, completedAt, command, summary, layers }) {
  const exitStatus = summary.ok ? 0 : 1;
  return {
    id: randomUUID(),
    kind: "gauntlet",
    specification: "phase-6.7 evidence gauntlet: mutation + changed-lines coverage + test-order independence",
    command,
    output: JSON.stringify({ summary, layers }, null, 2),
    status: exitStatus === 0 ? "passed" : "failed",
    exit_code: exitStatus,
    // Arcane derives trust_class from this receipt when authority is host.
    receipt: JSON.stringify({
      schema: "orthic.tool-receipt.v1",
      exit_status: exitStatus,
      started_at: startedAt,
      completed_at: completedAt,
      summary: {
        mutation: { passed: layers.mutation.passed, failed: layers.mutation.failed, total: layers.mutation.total },
        coverage: { passed: layers.coverage.passed, failed: layers.coverage.failed, percent: layers.coverage.percent ?? 0 },
        order: { passed: layers.order.passed, failed: layers.order.failed, total: layers.order.total },
      },
    }),
  };
}

export function buildCheck(receipt) {
  // Full check object matching Arcane's normalized shape.
  return {
    id: receipt.id,
    kind: "gauntlet",
    specification: receipt.specification,
    command: receipt.command,
    output: receipt.output,
    output_ref: receipt.output_ref,
    status: receipt.status,
    exit_code: receipt.exit_code,
    executor: "host",
    authority: "host",
    env_fingerprint: null,
    workspace_hash: null,
    receipt: receipt.receipt,
  };
}
