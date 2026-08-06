// Maven build provider: wrapper-integrity receipts and offline behavior. The
// wrapper is preferred over any unconfigured global build tool.

export function mavenWrapperReceipt({ root, wrapperPresent, wrapperSha256 }) {
  return {
    schemaVersion: 1,
    kind: 'nemesis-maven-wrapper',
    root,
    wrapperPresent: Boolean(wrapperPresent),
    wrapperSha256: wrapperSha256 ?? null,
    integrityVerified: wrapperSha256 ? true : false,
  };
}

export function mavenCommand({ root, offline = true, goals = ['compile'] }) {
  return {
    executable: './mvnw',
    args: [...goals, ...(offline ? ['-o'] : [])],
    cwd: root,
    timeoutMs: 300000,
    environmentKeys: ['PATH', 'HOME', 'MAVEN_ARGS'],
  };
}
