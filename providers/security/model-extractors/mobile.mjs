// Mobile extractor (B7-007): Android/iOS manifest and config repository text
// plus upstream package-manifest evidence from the Cortex projection.
// Extracts declared permissions, deep links, JS/native bridges, exported
// components, and backup/cleartext-traffic flags.
//
// Repository/config text and upstream projection facts only. No device
// connection, no emulator, no app install, no network probe of any kind.

import { entity, relation, fact, controlEntity } from './common.mjs';
import { assertEntityKind, assertRelationKind, assertFactKind, stableId } from '../contracts.mjs';

function typedEntity(kind, name, attributes, evidenceRefs, opts) {
  assertEntityKind(kind);
  return entity(kind, name, attributes, evidenceRefs, opts);
}

function typedRelation(kind, from, to, evidenceRefs, attributes, opts) {
  assertRelationKind(kind);
  return relation(kind, from, to, evidenceRefs, attributes, opts);
}

function typedFact(kind, fields, evidenceRefs) {
  assertFactKind(kind);
  return fact(kind, fields, evidenceRefs);
}

function typedControlEntity(controlType, name, evidenceRefs, attributes) {
  assertEntityKind('control');
  return controlEntity(controlType, name, evidenceRefs, attributes);
}

const MOBILE_FILE_PATTERN = /(^|\/)(AndroidManifest\.xml|.*\.gradle(\.kts)?|Info\.plist|.*\.plist|Podfile|capacitor\.config\.(json|ts|js)|ionic\.config\.json|app\.json|pubspec\.yaml)$/i;
const MOBILE_DEP_PATTERN = /^(react-native|expo|@capacitor\/core|cordova|@ionic\/)/i;

const ANDROID_PERMISSION_PATTERN = /<uses-permission[^>]*android:name="([^"]+)"/g;
const IOS_USAGE_DESCRIPTION_PATTERN = /<key>(NS\w*UsageDescription)<\/key>/g;
const INTENT_FILTER_CONTEXT_PATTERN = /<intent-filter\b[\s\S]*?<\/intent-filter>/g;
const ANDROID_SCHEME_PATTERN = /android:scheme="([^"]+)"/g;
const IOS_URL_SCHEME_PATTERN = /CFBundleURLSchemes/;
const APP_LINKS_PATTERN = /applinks:|android:autoVerify="true"/;
const JS_NATIVE_BRIDGE_PATTERN = /@ReactMethod|addJavascriptInterface|JavascriptInterface|WKScriptMessageHandler|NativeModules|evaluateJavascript|postMessage\s*\(/;
const EXPORTED_COMPONENT_PATTERN = /android:exported="true"/g;
const ALLOW_BACKUP_TRUE_PATTERN = /android:allowBackup="true"/;
const ALLOW_BACKUP_FALSE_PATTERN = /android:allowBackup="false"/;
const CLEARTEXT_ANDROID_PATTERN = /android:usesCleartextTraffic="true"/;
const CLEARTEXT_IOS_PATTERN = /NSAllowsArbitraryLoads<\/key>\s*<true\s*\/>/;

function isMobileDependency(projection) {
  const manifests = projection?.auditFacts?.packageManifests ?? [];
  for (const manifest of manifests) {
    for (const dep of manifest.dependencies ?? []) {
      if (MOBILE_DEP_PATTERN.test(dep)) return true;
    }
  }
  return false;
}

export function extractMobile({ root, plan, projection, files, lensRegistry }) {
  const entities = [];
  const relations = [];
  const evidence = [];
  const initialFacts = [];
  const coverageGaps = [];

  const sourceText = projection?.sourceText ?? {};
  let sawMobileSignal = isMobileDependency(projection);

  // JS/native bridge code lives in ordinary source files (.java/.kt/.swift/
  // .m/.js/.ts), not in the manifest/plist config files scanned below, so it
  // gets its own pass over the full denominator.
  for (const file of files ?? []) {
    const text = sourceText[file];
    if (!text) continue;
    if (JS_NATIVE_BRIDGE_PATTERN.test(text)) {
      sawMobileSignal = true;
      const evidenceRef = stableId('mobile-bridge-evidence', { file });
      const jsSource = typedEntity('source', `webview JS caller ${file}`, { file, sourceKind: 'webview-js', trust: 'untrusted' }, [evidenceRef]);
      const nativeSink = typedEntity('sink', `native bridge handler ${file}`, { file, sinkKind: 'native-bridge' }, [evidenceRef]);
      entities.push(jsSource, nativeSink);
      relations.push(typedRelation('calls', jsSource.id, nativeSink.id, [evidenceRef]));
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'JS/native bridge' });
    }
  }

  for (const file of files ?? []) {
    if (!MOBILE_FILE_PATTERN.test(file)) continue;

    const text = sourceText[file];
    if (text === undefined) {
      coverageGaps.push({
        kind: 'missing-rendered-configuration',
        domain: 'mobile',
        file,
        reason: 'file matched a mobile manifest/config pattern but no source text was projected for it',
      });
      continue;
    }
    if (!text) continue;
    sawMobileSignal = true;

    const permissionNames = new Set();
    for (const match of text.matchAll(ANDROID_PERMISSION_PATTERN)) permissionNames.add(match[1]);
    for (const match of text.matchAll(IOS_USAGE_DESCRIPTION_PATTERN)) permissionNames.add(match[1]);
    for (const name of permissionNames) {
      const evidenceRef = stableId('mobile-permission-evidence', { file, name });
      const permission = typedEntity('permission-scope', `declared permission ${name}`, { file, permission: name }, [evidenceRef]);
      entities.push(permission);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: `Declared permission ${name}` });
    }

    const deepLinkSchemes = new Set();
    for (const block of text.matchAll(INTENT_FILTER_CONTEXT_PATTERN)) {
      for (const match of block[0].matchAll(ANDROID_SCHEME_PATTERN)) deepLinkSchemes.add(match[1]);
    }
    const hasDeepLink = deepLinkSchemes.size > 0 || IOS_URL_SCHEME_PATTERN.test(text) || APP_LINKS_PATTERN.test(text);
    if (hasDeepLink) {
      const evidenceRef = stableId('mobile-deep-link-evidence', { file });
      const entrypoint = typedEntity(
        'entrypoint',
        `deep link entrypoint ${file}`,
        { file, entrypointType: 'deep-link', schemes: [...deepLinkSchemes].sort(), trust: 'untrusted' },
        [evidenceRef],
      );
      entities.push(entrypoint);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Deep link entrypoint' });
      initialFacts.push(typedFact('network-reachability', {
        subject: 'actor:external', action: 'reach', object: entrypoint.id, scope: 'mobile',
        attributes: { vector: 'deep-link' },
      }, [evidenceRef]));
    }

    if (EXPORTED_COMPONENT_PATTERN.test(text)) {
      const evidenceRef = stableId('mobile-exported-evidence', { file });
      const exported = typedEntity(
        'entrypoint',
        `exported component ${file}`,
        { file, entrypointType: 'exported-component' },
        [evidenceRef],
      );
      entities.push(exported);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Exported Android component' });
      initialFacts.push(typedFact('network-reachability', {
        subject: 'actor:external', action: 'reach', object: exported.id, scope: 'mobile',
        attributes: { vector: 'on-device-inter-app' },
      }, [evidenceRef]));
    }

    if (ALLOW_BACKUP_TRUE_PATTERN.test(text) || ALLOW_BACKUP_FALSE_PATTERN.test(text)) {
      const evidenceRef = stableId('mobile-backup-evidence', { file });
      const control = typedControlEntity('data-backup', `application backup policy ${file}`, [evidenceRef], {
        controlState: ALLOW_BACKUP_TRUE_PATTERN.test(text) ? 'absent' : 'enforced',
      });
      entities.push(control);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Application backup policy' });
    }

    if (CLEARTEXT_ANDROID_PATTERN.test(text) || CLEARTEXT_IOS_PATTERN.test(text)) {
      const evidenceRef = stableId('mobile-cleartext-evidence', { file });
      const control = typedControlEntity('transport-security', `cleartext traffic policy ${file}`, [evidenceRef], {
        controlState: 'absent',
      });
      entities.push(control);
      evidence.push({ id: evidenceRef, kind: 'source-location', file, description: 'Cleartext traffic allowed' });
    }
  }

  if (!sawMobileSignal) {
    coverageGaps.push({
      kind: 'mobile-context-not-detected',
      domain: 'mobile',
      reason: 'no mobile manifest/config file or mobile framework dependency found in the denominator',
    });
  }

  return { entities, relations, evidence, initialFacts, coverageGaps };
}
