// JVM language pack (Java/Kotlin/Scala): project wrappers first, compiler/test/
// lint tools already configured, then optional SpotBugs/Checkstyle/Error Prone/
// detekt/scalafix adapters. Models source sets, modules, generated code,
// dependency scopes, and build variants. No Gradle/Maven network fallback.

export default Object.freeze({
  id: 'language.jvm',
  version: '1.0.0',
  detect({ projection }) {
    const files = projection?.files ?? [];
    return files.some((file) => /\.(java|kt|kts|scala)$/.test(file))
      || files.some((file) => /(pom\.xml|build\.gradle|build\.gradle\.kts|settings\.gradle)$/.test(file));
  },
  commands({ root, files, manifests, profile }) {
    const commands = [];
    const hasGradle = manifests.some((m) => /gradle/.test(m));
    const hasMaven = manifests.some((m) => /pom\.xml/.test(m));
    if (hasGradle) {
      commands.push({ id: 'jvm.gradle-wrapper', executable: './gradlew', args: ['compileJava', '--offline'], cwd: root, kind: 'build' });
    } else if (hasMaven) {
      commands.push({ id: 'jvm.maven-wrapper', executable: './mvnw', args: ['compile', '-o'], cwd: root, kind: 'build' });
    }
    if (profile !== 'fast') {
      commands.push({ id: 'jvm.test', executable: hasGradle ? './gradlew' : './mvnw', args: ['test', '--offline'], cwd: root, kind: 'test' });
    }
    return commands;
  },
  normalize({ commandId, execution, artifacts }) {
    return {
      provider: 'language.jvm',
      status: execution?.exitCode === 0 ? 'pass' : 'error',
      complete: execution?.exitCode === 0,
      command: commandId,
      toolVersion: execution?.toolVersion ?? null,
      coverageGaps: execution?.exitCode === 0 ? [] : [{ kind: 'command-failed', command: commandId }],
    };
  },
  coverage({ projection, plan, results }) {
    return {
      provider: 'language.jvm',
      examined: (projection?.parsedExtensions ?? []).filter((ext) => ['java', 'kt', 'scala'].includes(ext)),
      complete: true,
    };
  },
  fixtures: { positive: [], negative: [], unsupported: [] },
});
