// Apple platform framework pack: entitlements/privacy/ATS/keychain/deeplink/
// WebView/update/notarization.

export default Object.freeze({
  id: 'framework.apple',
  version: '1.0.0',
  detect({ projection }) {
    const files = projection?.files ?? [];
    return files.some((file) => /\.(swift|m|mm)$/.test(file))
      || files.some((file) => /(\.entitlements|Info\.plist|\.xcodeproj)/.test(file));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/NSAllowsArbitraryLoads\s*=\s*true/.test(text) || /NSAllowsArbitraryLoads<\/key>\s*<true\/>/.test(text)) {
        observations.push({ ruleId: 'apple.ats-disabled', severityHint: 'high', claim: 'ATS (arbitrary loads) is disabled.', file });
      }
      if (/NSAllowsArbitraryLoadsInWebContent\s*=\s*true/.test(text)) {
        observations.push({ ruleId: 'apple.ats-webview', severityHint: 'medium', claim: 'ATS disabled in WebView content.', file });
      }
      if (/UIWebView\b|WKWebView[\s\S]{0,200}javaScriptEnabled\s*=\s*true/.test(text)) {
        observations.push({ ruleId: 'apple.webview-js', severityHint: 'medium', claim: 'WebView enables JavaScript without visible boundary.', file });
      }
      if (/https?:\/\/[^"']*\/\/(?:callback|oauth|auth)/.test(text) && !/state|pkce|code_verifier/.test(text)) {
        observations.push({ ruleId: 'apple.oauth-callback', severityHint: 'medium', claim: 'OAuth callback without visible state/PKCE.', file });
      }
      if (/UserDefaults\.standard\.set\s*\([^)]*(?:token|secret|key)/.test(text)) {
        observations.push({ ruleId: 'apple.storage-sensitive', severityHint: 'high', claim: 'Sensitive value stored in UserDefaults.', file });
      }
    }
    return observations;
  },
});
