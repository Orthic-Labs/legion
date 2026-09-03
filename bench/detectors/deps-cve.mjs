// Bench-local dependency-CVE detector (offline, deterministic).
// Curated table of a small number of well-known, long-since-patched CVEs.
// This intentionally mirrors what `npm audit`/`deps_cve` in collect-facts.mjs
// checks in production, but runs from a static local table instead of a live
// registry call, so the bench works with no network.

const KNOWN_VULNERABLE = {
  lodash: [{ range: "<4.17.21", advisory: "CVE-2020-8203 / CVE-2019-10744 prototype pollution" }],
  minimist: [{ range: "<1.2.6", advisory: "CVE-2021-44906 prototype pollution" }],
};

function versionLessThan(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na !== nb) return na < nb;
  }
  return false;
}

/**
 * @param {object} pkgJson parsed package.json
 * @returns {{name:string, version:string, advisory:string}[]}
 */
export function scanDeps(pkgJson) {
  const findings = [];
  const deps = { ...(pkgJson.dependencies || {}), ...(pkgJson.devDependencies || {}) };
  for (const [name, version] of Object.entries(deps)) {
    const rules = KNOWN_VULNERABLE[name];
    if (!rules) continue;
    const clean = String(version).replace(/^[\^~]/, "");
    for (const rule of rules) {
      const bound = rule.range.replace("<", "");
      if (versionLessThan(clean, bound)) {
        findings.push({ name, version: clean, advisory: rule.advisory });
      }
    }
  }
  return findings;
}
