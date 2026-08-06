import assert from 'node:assert/strict';
import test from 'node:test';
import swiftPack from '../../../providers/native/swift-objc/index.mjs';
import dartPack from '../../../providers/native/dart/index.mjs';
import applePack from '../../../providers/frameworks/apple/index.mjs';
import flutterPack from '../../../providers/frameworks/flutter/index.mjs';
import reactNativePack from '../../../providers/frameworks/react-native/index.mjs';

const projection = (files = [], deps = []) => ({ files, parsedExtensions: files.map((f) => f.split('.').pop()), auditFacts: { packageManifests: deps } });

test('swift pack detects Swift projects', () => {
  assert.equal(swiftPack.detect({ projection: projection(['Package.swift']) }), true);
  assert.equal(swiftPack.detect({ projection: projection(['a.py']) }), false);
});

test('swift pack degrades on non-macOS hosts', () => {
  const commands = swiftPack.commands({ root: '/repo', files: ['a.swift'], manifests: ['Package.swift'], profile: 'standard', platform: 'linux' });
  assert.ok(commands.some((c) => c.kind === 'degraded'));
  const result = swiftPack.normalize({ commandId: 'swift.degraded', execution: { degraded: true, reason: 'requires macOS' }, artifacts: {} });
  assert.equal(result.status, 'unproven');
  assert.ok(result.coverageGaps.some((g) => g.kind === 'host-limited'));
});

test('swift pack emits build/test/lint on macOS', () => {
  const commands = swiftPack.commands({ root: '/repo', files: ['a.swift'], manifests: ['Package.swift'], profile: 'standard', platform: 'darwin' });
  assert.ok(commands.some((c) => c.id === 'swift.build'));
  assert.ok(commands.some((c) => c.id === 'swift.lint'));
});

test('dart pack detects pubspec projects', () => {
  assert.equal(dartPack.detect({ projection: projection(['pubspec.yaml']) }), true);
});

test('dart pack emits analyze/test', () => {
  const commands = dartPack.commands({ root: '/repo', files: ['a.dart'], manifests: ['pubspec.yaml'], profile: 'standard' });
  assert.ok(commands.some((c) => c.id === 'dart.analyze'));
  assert.ok(commands.some((c) => c.id === 'dart.test'));
});

test('apple pack flags ATS disabled', () => {
  const observations = applePack.analyze({ files: ['Info.plist'], readFile: () => '<key>NSAllowsArbitraryLoads</key><true/>' });
  assert.ok(observations.some((o) => o.ruleId === 'apple.ats-disabled'));
});

test('apple pack flags sensitive UserDefaults storage', () => {
  const observations = applePack.analyze({ files: ['Auth.swift'], readFile: () => 'UserDefaults.standard.set(token, forKey: "auth")' });
  assert.ok(observations.some((o) => o.ruleId === 'apple.storage-sensitive'));
});

test('flutter pack flags bad cert callback', () => {
  const observations = flutterPack.analyze({ files: ['main.dart'], readFile: () => 'badCertificateCallback: (cert, host, port) => true' });
  assert.ok(observations.some((o) => o.ruleId === 'flutter.bad-cert-callback'));
});

test('flutter pack flags sensitive SharedPreferences storage', () => {
  const observations = flutterPack.analyze({ files: ['store.dart'], readFile: () => 'SharedPreferences.getInstance(); prefs.setString("token", token)' });
  assert.ok(observations.some((o) => o.ruleId === 'flutter.storage-sensitive'));
});

test('react-native pack flags unvalidated openURL', () => {
  const observations = reactNativePack.analyze({ files: ['App.js'], readFile: () => 'Linking.openURL(url)' });
  assert.ok(observations.some((o) => o.ruleId === 'react-native.openurl-unvalidated'));
});

test('react-native pack flags sensitive AsyncStorage', () => {
  const observations = reactNativePack.analyze({ files: ['store.js'], readFile: () => 'AsyncStorage.setItem("token", token)' });
  assert.ok(observations.some((o) => o.ruleId === 'react-native.storage-sensitive'));
});
