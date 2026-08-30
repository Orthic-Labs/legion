import { CapabilityStore } from '../../../src/lib/guard/compat/effects/capability-store.mjs';
const [root, rawGrant, requestId, mode] = process.argv.slice(2);
const grant = JSON.parse(rawGrant);
const store = new CapabilityStore({ root, clock: () => Date.parse(grant.issuedAt) }); store.issue(grant);
try { const value = mode === 'revoke' ? store.revoke(grant.capabilityId, 'race') : store.consume(grant.capabilityId, { ...grant, requestId, now: grant.issuedAt }); process.stdout.write(JSON.stringify({ ok: true, value })); } catch (error) { process.stdout.write(JSON.stringify({ ok: false, code: error.code })); }
