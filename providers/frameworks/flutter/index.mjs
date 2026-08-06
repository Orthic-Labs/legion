// Flutter framework pack: widget/lifecycle/navigation/platform channels/
// storage/network/release.

export default Object.freeze({
  id: 'framework.flutter',
  version: '1.0.0',
  detect({ projection }) {
    const files = projection?.files ?? [];
    return files.some((file) => /\.dart$/.test(file))
      && (projection?.auditFacts?.packageManifests ?? []).some((m) => /flutter/.test(JSON.stringify(m)));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      if (!/\.dart$/.test(file)) continue;
      const text = readFile(file) ?? '';
      if (/badCertificateCallback\s*[:=]\s*[\s\S]{0,80}?=>\s*true/.test(text)) {
        observations.push({ ruleId: 'flutter.bad-cert-callback', severityHint: 'high', claim: 'All TLS certificates accepted.', file });
      }
      if (/JavaScriptMode\.unrestricted/.test(text)) {
        observations.push({ ruleId: 'flutter.webview-js-unrestricted', severityHint: 'medium', claim: 'WebView enables unrestricted JavaScript.', file });
      }
      if (/MethodChannel\s*\([^)]*\)/.test(text) && !/invokeMethod|setMethodCallHandler/.test(text)) {
        observations.push({ ruleId: 'flutter.unscoped-channel', severityHint: 'low', claim: 'Platform channel without visible handler.', file });
      }
      if (/SharedPreferences|shared_preferences/.test(text) && /token|secret|password/.test(text)) {
        observations.push({ ruleId: 'flutter.storage-sensitive', severityHint: 'high', claim: 'Sensitive value stored in SharedPreferences.', file });
      }
    }
    return observations;
  },
});
