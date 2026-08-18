import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.high-consequence', family: 'high-consequence', description: 'Smart-contract, embedded, industrial, and high-consequence safety boundaries.', rules: [
  { id: 'smart-contract.tx-origin-auth', pattern: /tx\.origin\s*==|require\s*\(\s*tx\.origin/i, claim: 'A smart contract may authorize callers through tx.origin.', severityHint: 'high', effectKind: 'principal-access' },
  { id: 'embedded.update-without-verification', pattern: /(?:firmware|ota|flash)[\s\S]{0,180}(?:download|apply)(?![\s\S]{0,120}(?:signature|verify|digest))/i, claim: 'A firmware update path has no visible authenticity verification.', severityHint: 'high', effectKind: 'code-execution' },
  { id: 'safety.command-without-interlock', pattern: /(?:actuator|motor|valve|relay)\.(?:start|open|enable|write)\s*\((?![^)]*(?:interlock|limit|safe))/i, claim: 'A physical control command has no visible safety interlock.', severityHint: 'high', effectKind: 'integrity-impact' },
] });
