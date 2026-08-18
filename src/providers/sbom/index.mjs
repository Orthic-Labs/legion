// Syft SBOM provider per SNIP-SYFT-01. Produces CycloneDX JSON and SPDX JSON
// as immutable run artifacts, recording package count, source scope, Syft
// version, and output digests.

export function syftCommand({ resolvedSyft, cycloneDxPath, spdxPath, repositoryRoot, policy }) {
  return {
    executable: resolvedSyft,
    args: [
      `dir:${repositoryRoot}`,
      '-o', `cyclonedx-json=${cycloneDxPath}`,
      '-o', `spdx-json=${spdxPath}`,
    ],
    cwd: repositoryRoot,
    timeoutMs: policy?.providerTimeoutMs ?? 120000,
    maxOutputBytes: policy?.maxOutputBytes ?? 8388608,
    environmentKeys: ['PATH', 'HOME', 'USERPROFILE', 'TEMP', 'TMP'],
  };
}

export function sbomReceipt({ providerVersion, packageCount, sourceScope, syftVersion, cycloneDxDigest, spdxDigest, cycloneDxPath, spdxPath }) {
  return {
    schemaVersion: 1,
    kind: 'legion-sbom-receipt',
    provider: 'sbom.syft',
    providerVersion,
    packageCount,
    sourceScope,
    toolVersion: syftVersion,
    artifacts: [
      { kind: 'cyclonedx-json', path: cycloneDxPath, digest: cycloneDxDigest },
      { kind: 'spdx-json', path: spdxPath, digest: spdxDigest },
    ],
  };
}
