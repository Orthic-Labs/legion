import assert from 'node:assert/strict';
import test from 'node:test';
import jvmPack from '../../../providers/native/jvm/index.mjs';
import springPack from '../../../providers/frameworks/spring/index.mjs';
import ktorPack from '../../../providers/frameworks/ktor/index.mjs';
import { mavenCommand, mavenWrapperReceipt } from '../../../providers/build/maven/index.mjs';
import { gradleCommand, gradleWrapperReceipt } from '../../../providers/build/gradle/index.mjs';

const projection = (files = [], deps = []) => ({ files, parsedExtensions: files.map((f) => f.split('.').pop()), auditFacts: { packageManifests: deps } });

test('jvm pack detects java/kotlin/scala projects', () => {
  assert.equal(jvmPack.detect({ projection: projection(['pom.xml']) }), true);
  assert.equal(jvmPack.detect({ projection: projection(['Main.kt']) }), true);
  assert.equal(jvmPack.detect({ projection: projection(['a.py']) }), false);
});

test('jvm pack prefers the wrapper over global tools', () => {
  const commands = jvmPack.commands({ root: '/repo', files: ['a.java'], manifests: ['build.gradle'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'jvm.gradle-wrapper'));
  assert.ok(commands[0].executable.startsWith('./'), 'wrapper must be preferred');
  const maven = jvmPack.commands({ root: '/repo', files: ['a.java'], manifests: ['pom.xml'], profile: 'standard' });
  assert.ok(maven.some((c) => c.id === 'jvm.maven-wrapper'));
});

test('jvm pack runs offline', () => {
  const commands = jvmPack.commands({ root: '/repo', files: ['a.java'], manifests: ['build.gradle'], profile: 'standard' });
  for (const command of commands) {
    assert.ok(command.args.some((a) => a === '--offline' || a === '-o'), `${command.id} must run offline`);
  }
});

test('jvm pack normalizes execution', () => {
  const result = jvmPack.normalize({ commandId: 'jvm.test', execution: { exitCode: 0 }, artifacts: {} });
  assert.equal(result.status, 'pass');
});

test('spring pack flags CSRF disable and SpEL input', () => {
  const observations = springPack.analyze({
    files: ['SecurityConfig.java'],
    readFile: () => 'http.csrf(csrf -> csrf.disable())\nSpelExpressionParser parser = new SpelExpressionParser(); parser.parseExpression(input);',
  });
  assert.ok(observations.some((o) => o.ruleId === 'spring.csrf-disabled'));
  assert.ok(observations.some((o) => o.ruleId === 'spring.spel-input'));
});

test('spring pack flags permitAll on sensitive routes', () => {
  const observations = springPack.analyze({ files: ['C.java'], readFile: () => 'requestMatchers("/admin/**").permitAll()' });
  assert.ok(observations.some((o) => o.ruleId === 'spring.sensitive-permit-all'));
});

test('ktor pack flags anyHost CORS', () => {
  const observations = ktorPack.analyze({ files: ['App.kt'], readFile: () => 'install(CORS) { anyHost() }' });
  assert.ok(observations.some((o) => o.ruleId === 'ktor.cors-any-host'));
});

test('ktor pack flags sensitive routes without auth', () => {
  const observations = ktorPack.analyze({ files: ['App.kt'], readFile: () => 'route("/admin") { get { call.respond("x") } }' });
  assert.ok(observations.some((o) => o.ruleId === 'ktor.sensitive-route-no-auth'));
});

test('maven wrapper receipt verifies integrity', () => {
  const receipt = mavenWrapperReceipt({ root: '/repo', wrapperPresent: true, wrapperSha256: 'sha256:w' });
  assert.equal(receipt.integrityVerified, true);
  assert.equal(mavenWrapperReceipt({ root: '/repo', wrapperPresent: true }).integrityVerified, false);
});

test('maven command is offline by default', () => {
  const contract = mavenCommand({ root: '/repo' });
  assert.equal(contract.executable, './mvnw');
  assert.ok(contract.args.includes('-o'));
});

test('gradle wrapper receipt requires both digests', () => {
  const receipt = gradleWrapperReceipt({ root: '/repo', wrapperPresent: true, wrapperSha256: 'sha256:w', distributionSha256: 'sha256:d' });
  assert.equal(receipt.integrityVerified, true);
  assert.equal(gradleWrapperReceipt({ root: '/repo', wrapperPresent: true }).integrityVerified, false);
});

test('gradle command is offline by default', () => {
  const contract = gradleCommand({ root: '/repo' });
  assert.equal(contract.executable, './gradlew');
  assert.ok(contract.args.includes('--offline'));
});
