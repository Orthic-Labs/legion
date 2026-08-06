// Neutral patch verification per SNIP-FIX-01: the patch producer never
// verifies its own result. Verification reruns the affected provider closure
// plus required baseline gates.

export function verifyPatch({ proposal, affectedProviderResults, baselineGates }) {
  const providersPass = (affectedProviderResults ?? []).every((result) => result.complete && result.status === 'pass');
  const gatesPass = (baselineGates ?? []).every((gate) => gate.passed === true);
  return {
    schemaVersion: 1,
    kind: 'nemesis-patch-verification',
    proposalId: proposal?.id ?? null,
    patchDigest: proposal?.patch?.digest ?? null,
    verifiedBy: 'neutral-verification', // never the patch producer
    providersPass,
    gatesPass,
    valid: providersPass && gatesPass,
    coverageGaps: [
      ...(providersPass ? [] : [{ kind: 'affected-provider-failed' }]),
      ...(gatesPass ? [] : [{ kind: 'baseline-gate-failed' }]),
    ],
  };
}
