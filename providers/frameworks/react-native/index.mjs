// React Native framework pack: JS/TS plus native bridge/mobile manifest packs
// (deep links, storage, permissions, update).

export default Object.freeze({
  id: 'framework.react-native',
  version: '1.0.0',
  detect({ projection }) {
    const deps = projection?.auditFacts?.packageManifests ?? [];
    return deps.some((m) => /react-native|expo/.test(JSON.stringify(m)));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/Linking\.openURL\s*\([^)]*(?:url|input|request)/.test(text) && !/canOpenURL|allowlist/.test(text)) {
        observations.push({ ruleId: 'react-native.openurl-unvalidated', severityHint: 'high', claim: 'External URL opened without visible validation.', file });
      }
      if (/NativeModules\.|requireNativeComponent\s*\(/.test(text) && !/checkPermissions|hasPermission/.test(text)) {
        observations.push({ ruleId: 'react-native.unscoped-bridge', severityHint: 'medium', claim: 'Native bridge without visible permission check.', file });
      }
      if (/AsyncStorage|MMKV/.test(text) && /token|secret|password/.test(text)) {
        observations.push({ ruleId: 'react-native.storage-sensitive', severityHint: 'high', claim: 'Sensitive value in async local storage.', file });
      }
    }
    return observations;
  },
});
