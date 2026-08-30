// S05 seal compiler: no requirement reaches a seal without its executable lifecycle.
import { decision } from '../../contracts/arcane/errors.mjs';
import { verifyExternalProviderCapability } from './provider-capability.mjs';

const REQUIRED_STEPS = ['producer', 'durableStore', 'authenticatedPersistence', 'verifier', 'completionConsumer', 'closePath'];
export function compileSealReachability({ requirements = [], providerCapabilities = [], recoveryPaths = [] } = {}) {
  const capabilities = new Map(providerCapabilities.map((capability) => [capability.providerId, capability]));
  const failures = [];
  for (const requirement of requirements) {
    const missing = REQUIRED_STEPS.filter((step) => requirement?.[step] !== true && !requirement?.[step]);
    if (missing.length) { failures.push({ requirementId: requirement?.id ?? null, reason: 'missing-lifecycle-step', missing }); continue; }
    if (requirement.producer === requirement.verifier || requirement.producer === requirement.completionConsumer || requirement.selfAttested === true || requirement.fixtureOnly === true || requirement.genericReceipt === true) {
      failures.push({ requirementId: requirement.id, reason: 'self-attested-or-nonproduction-path' }); continue;
    }
    if (requirement.externalProvider) {
      const cap = capabilities.get(requirement.externalProvider);
      const capability = verifyExternalProviderCapability(cap, { providerId: requirement.externalProvider });
      if (!capability.allowed) {
        failures.push({ requirementId: requirement.id, reason: 'external-provider-capability-unreachable', providerId: requirement.externalProvider }); continue;
      }
    }
    if (!recoveryPaths.some((path) => path.requirementId === requirement.id && path.authenticated === true && path.closePath === true)) failures.push({ requirementId: requirement.id, reason: 'recovery-close-unreachable' });
  }
  if (failures.length) return decision({ allowed: false, code: 'ARC_UNSOUND_SEAL', message: 'required evidence lifecycle is not reachable', detail: { status: 'UNSOUND_SEAL', failures } });
  return decision({ allowed: true, message: 'every required evidence lifecycle is reachable', detail: { status: 'SOUND_SEAL', requirements: requirements.map((entry) => entry.id) } });
}
