import { digest, sameBinding } from './binding.mjs';

export async function verifySealedRun({ priorRun, currentRepository }, host) {
  const prior = typeof priorRun === 'string' ? JSON.parse(await host.fs.readFile(priorRun, 'utf8')) : priorRun;
  const currentBinding = currentRepository?.binding ?? currentRepository ?? null;
  const expectedBinding = prior?.binding ?? prior?.plan?.binding ?? null;
  const valid = Boolean(prior && expectedBinding && sameBinding(expectedBinding, currentBinding));
  return { schemaVersion: 1, kind: 'nemesis-verification-receipt', valid, priorDigest: digest(prior ?? null), binding: currentBinding, status: valid ? 'pass' : 'unproven', gaps: valid ? [] : [{ kind: 'binding-drift' }], verifiedAt: host.clock.now().toISOString() };
}
