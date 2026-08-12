import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { validateExecutableContract, collectExecutableContractErrors } from '../../contracts/executable.mjs';
import { ArcaneError } from './errors.mjs';
import { canonicalJson, digestValue } from './canonical.mjs';
import { RuntimeSchemaSet } from './runtime-schema.mjs';
import { stateFile } from './state-paths.mjs';
import { requireCanonicalAdvisoryProfile } from './advisory-profile.mjs';

const schema = new RuntimeSchemaSet();
const fail = (code, message, detail = {}) => { throw new ArcaneError(code, message, detail); };
const same = (a, b) => canonicalJson(a) === canonicalJson(b);
export class ContractSealStore {
  #root; #clock; #manifestRoot;
  constructor({ root, clock = () => new Date().toISOString(), manifestRoot } = {}) { this.#root = root; this.#clock = clock; this.#manifestRoot = manifestRoot; }
  #path(contractId, version) { return stateFile(this.#root, 'arcane.contract-seal.key.v1', [contractId, version]); }
  #read(path) { try { const record = JSON.parse(readFileSync(path, 'utf8')); if (schema.validate('arcane-contract-seal-v1', record).length) fail('ARC_STORE_CORRUPT', 'invalid stored contract seal'); return record; } catch (e) { if (e instanceof ArcaneError) throw e; fail('ARC_STORE_CORRUPT', 'unreadable contract seal'); } }
  seal({ contract, authorityAssertion, dispatchDigest = null }) {
    try { requireCanonicalAdvisoryProfile(contract?.advisoryProfile, { manifestRoot: this.#manifestRoot }); } catch (error) { fail(error.code ?? 'ARC_PROFILE_BINDING_MISMATCH', error.message, error.detail); }
    const errors = collectExecutableContractErrors(contract); if (errors.length) fail(errors.some((e) => e.code === 'G9_OPEN_QUESTIONS_NONEMPTY' || e.code.startsWith('EXEC_')) ? 'ARC_CONTRACT_NOT_EXECUTABLE' : 'ARC_SCHEMA_INVALID', errors[0].message);
    try { validateExecutableContract(contract); } catch { fail('ARC_CONTRACT_NOT_EXECUTABLE', 'contract is not executable'); }
    if (!authorityAssertion || authorityAssertion.authority !== 'sage' || typeof authorityAssertion.assertedBy !== 'string' || !authorityAssertion.assertedBy || authorityAssertion.verificationMethod !== 'capability-signature' || authorityAssertion.perMessage !== true) fail('ARC_SCHEMA_INVALID', 'invalid Sage authority assertion');
    const record = { schemaVersion: 1, kind: 'arcane-contract-seal', contractId: contract.contractId, version: contract.version, sourceRevision: contract.sourceRevision, contractDigest: digestValue(contract), dispatchDigest, sealedBy: { authority: 'sage', assertedBy: authorityAssertion.assertedBy, verificationMethod: 'capability-signature', perMessage: true }, sealedAt: this.#clock(), contract };
    if (schema.validate('arcane-contract-seal-v1', record).length) fail('ARC_SCHEMA_INVALID', 'invalid contract seal');
    const path = this.#path(record.contractId, record.version); mkdirSync(this.#root, { recursive: true });
    let fd; try { fd = openSync(path, 'wx', 0o600); const bytes = Buffer.from(`${canonicalJson(record)}\n`); for (let at = 0; at < bytes.length;) at += writeSync(fd, bytes, at); fsyncSync(fd); closeSync(fd); return { ok: true, created: true, record }; } catch (e) { if (fd !== undefined) closeSync(fd); if (e.code !== 'EEXIST') fail('ARC_STORE_CORRUPT', 'cannot write contract seal'); }
    const existing = this.#read(path); const fields = ['contractId', 'version', 'sourceRevision', 'contractDigest', 'dispatchDigest'];
    if (!fields.every((field) => existing[field] === record[field]) || !same(existing.contract, contract) || existing.sealedBy.authority !== 'sage' || existing.sealedBy.verificationMethod !== 'capability-signature' || existing.sealedBy.perMessage !== true) fail('ARC_CONTRACT_VERSION_MISMATCH', 'contract seal conflicts with immutable version');
    return { ok: true, created: false, record: existing };
  }
  get(contractId, version) { try { return this.#read(this.#path(contractId, version)); } catch (e) { if (e.code === 'ARC_STORE_CORRUPT') return null; throw e; } }
  require(contract) { try { requireCanonicalAdvisoryProfile(contract?.advisoryProfile, { manifestRoot: this.#manifestRoot }); } catch (error) { fail(error.code ?? 'ARC_PROFILE_BINDING_MISMATCH', error.message, error.detail); } const record = this.get(contract.contractId, contract.version); if (!record) fail('ARC_NO_CONTRACT', 'contract seal missing'); if (record.sourceRevision !== contract.sourceRevision || record.contractDigest !== digestValue(contract) || !same(record.contract, contract)) fail('ARC_CONTRACT_VERSION_MISMATCH', 'contract seal identity mismatch'); return record; }
  verify(contractId, version) { try { const record = this.get(contractId, version); if (!record) return { ok: false, code: 'ARC_STORE_CORRUPT', issues: ['missing'] }; this.require(record.contract); return { ok: true, code: null, issues: [] }; } catch (e) { return { ok: false, code: 'ARC_STORE_CORRUPT', issues: [e.message] }; } }
}
