// Gradle build provider: wrapper-integrity receipts, offline behavior, and
// build variants. No network fallback during offline runs.

export function gradleWrapperReceipt({ root, wrapperPresent, wrapperSha256, distributionSha256 }) {
  return {
    schemaVersion: 1,
    kind: 'legion-gradle-wrapper',
    root,
    wrapperPresent: Boolean(wrapperPresent),
    wrapperSha256: wrapperSha256 ?? null,
    distributionSha256: distributionSha256 ?? null,
    integrityVerified: Boolean(wrapperSha256 && distributionSha256),
  };
}

export function gradleCommand({ root, offline = true, tasks = ['compileJava'] }) {
  return {
    executable: './gradlew',
    args: [...tasks, ...(offline ? ['--offline'] : [])],
    cwd: root,
    timeoutMs: 300000,
    environmentKeys: ['PATH', 'HOME', 'GRADLE_OPTS'],
  };
}
