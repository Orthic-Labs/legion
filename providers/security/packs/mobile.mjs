// Mobile security pack per Security Appendix §54.3. Exported components,
// deep links, WebViews, storage, auth callbacks, signing/update. Repository/
// configuration evidence only; no device requirement.

export default Object.freeze({
  id: 'security.mobile',
  version: '1.0.0',
  candidateClass: 'mobile',
  description: 'Android/iOS/mobile framework manifests and source.',
  rules: [
    { id: 'mobile.exported-component-no-permission' },
    { id: 'mobile.webview-js-bridge' },
    { id: 'mobile.storage-sensitive' },
  ],
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes.path === file);
      if (/android:exported="true"/.test(text) && !/android:permission=/.test(text)) {
        observations.push({
          ruleId: 'mobile.exported-component-no-permission',
          candidateClass: 'mobile',
          claim: 'An exported Android component has no visible permission gate.',
          severityHint: 'high',
          sources: artifact ? [artifact.id] : [], sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['external-activity-launch'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'launch-component', environment: 'mobile' }],
          effects: [{ kind: 'object-access', subject: 'actor:external', action: 'read', object: artifact?.id ?? null, scope: 'cross-app', environment: 'mobile', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['starter'], evidenceRefs: [],
          detectorMetadata: { file },
          uncertainty: ['Caller checks may exist outside the manifest.'],
        });
      }
      if (/setJavaScriptEnabled\s*\(\s*true/.test(text) && /addJavascriptInterface|evaluateJavascript/.test(text)) {
        observations.push({
          ruleId: 'mobile.webview-js-bridge',
          candidateClass: 'mobile',
          claim: 'WebView enables JavaScript with a native bridge.',
          severityHint: 'high',
          sources: artifact ? [artifact.id] : [], sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['control-webview-content'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'control-webview-content', environment: 'mobile' }],
          effects: [{ kind: 'code-execution', subject: 'actor:external', action: 'execute', object: artifact?.id ?? null, scope: 'native-bridge', environment: 'mobile', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['enabler', 'impact'], evidenceRefs: [],
          detectorMetadata: { file },
          uncertainty: ['Bridge method allowlists may limit exposure.'],
        });
      }
    }
    return observations;
  },
  variantStrategies: {},
});
