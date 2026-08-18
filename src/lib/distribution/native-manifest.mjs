import { existsSync, statSync } from 'node:fs';
import { fileDigest } from './release-manifest.mjs';

export function nativeBuildManifest({ platform, architecture, nodeBinary, nodeVersion, seaConfigDigest, packageDigest, assets, executable, sourceRevision = null }) {
  const executablePresent = Boolean(executable && existsSync(executable));
  return {
    schemaVersion: 1,
    kind: 'legion-native-build',
    platform,
    architecture,
    nodeBinary,
    nodeVersion,
    sourceRevision,
    seaConfigDigest,
    packageDigest,
    assets,
    executable: executablePresent ? executable : null,
    executableDigest: executablePresent ? fileDigest(executable) : null,
    executableMode: executablePresent ? statSync(executable).mode & 0o777 : null,
    rustCrate: false,
    blobInjected: executablePresent,
    decision: executablePresent ? 'QUALIFIED' : 'BLOCKED',
    blockers: executablePresent ? [] : [{ kind: 'native-executable-absent', required: 'postject injection tool and successful executable build' }],
  };
}
