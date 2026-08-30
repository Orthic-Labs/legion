import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { ContractSealStore } from '../../../src/lib/cli/commands/governance/delivery/contract-seal-store.mjs';
const { root, contract, authorityAssertion } = JSON.parse(process.env.ARCANE_SEAL_RACE);
mkdirSync(process.env.ARCANE_SEAL_READY, { recursive: true }); writeFileSync(`${process.env.ARCANE_SEAL_READY}/${process.pid}`, 'ready');
while (!existsSync(process.env.ARCANE_SEAL_START)) await new Promise((resolve) => setTimeout(resolve, 10));
try { process.stdout.write(JSON.stringify(new ContractSealStore({ root }).seal({ contract, authorityAssertion }))); }
catch (error) { process.stdout.write(JSON.stringify({ error: error.code })); }
