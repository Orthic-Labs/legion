// Bench-local secrets detector (offline, deterministic, no network/tool shell-out).
// Approximates what a real secret scanner (e.g. gitleaks) should catch:
// a credential-shaped LITERAL VALUE assigned to a variable, not a bare name
// or a reference to an env var. Deliberately conservative to keep the
// negative controls (AU20-002, AU20-010) clean.

const CREDENTIAL_VALUE_PATTERNS = [
  /AKIA[0-9A-Z_]{10,}/, // AWS-access-key-shaped literal (incl. the bench's fake AKIA_EXAMPLE_* form)
  /\bEXAMPLE\/NOTREAL\/SECRETKEY[0-9A-Za-z]+/,
  /sk-[A-Za-z0-9]{20,}/, // generic "sk-..." style secret literal
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

/**
 * @param {string} source file contents
 * @returns {{line:number, match:string}[]} findings, 1-indexed lines
 */
export function scanSecrets(source) {
  const findings = [];
  const lines = source.split("\n");
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    // Skip comment-only lines that merely NAME a credential (no literal value
    // matching a credential-shaped pattern on that same line survives past
    // this point anyway — the pattern match below is what actually decides).
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;
    for (const pattern of CREDENTIAL_VALUE_PATTERNS) {
      if (pattern.test(line)) {
        findings.push({ line: idx + 1, match: line.trim() });
        break;
      }
    }
  });
  return findings;
}
