// Mobile language bench: swift degradation, dart commands, and framework
// observations.
import swiftPack from '../../../providers/native/swift-objc/index.mjs';
import dartPack from '../../../providers/native/dart/index.mjs';
import applePack from '../../../providers/frameworks/apple/index.mjs';
import flutterPack from '../../../providers/frameworks/flutter/index.mjs';

const swiftLinux = swiftPack.commands({ root: '/repo', files: ['a.swift'], manifests: ['Package.swift'], profile: 'standard', platform: 'linux' });
const dartCommands = dartPack.commands({ root: '/repo', files: ['a.dart'], manifests: ['pubspec.yaml'], profile: 'standard' });
const appleObs = applePack.analyze({ files: ['Info.plist'], readFile: () => '<key>NSAllowsArbitraryLoads</key><true/>' }).length;
const flutterObs = flutterPack.analyze({ files: ['main.dart'], readFile: () => 'badCertificateCallback: (c,h,p) => true' }).length;

console.log(`mobile bench: swift-degraded=${swiftLinux.length}, dart=${dartCommands.length}, apple=${appleObs}, flutter=${flutterObs}`);
if (!swiftLinux.some((c) => c.kind === 'degraded')) process.exit(1);
if (dartCommands.length < 2) process.exit(1);
if (appleObs < 1 || flutterObs < 1) process.exit(1);
console.log('GATE: PASS');
