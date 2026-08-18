// Mobile security pack (B7-020). Android/iOS manifest, config, and source
// text only — no device, emulator, app-store, or network connection of any
// kind. Consumes the mobile model-extractor's entities (permission-scope,
// deep-link/exported-component entrypoints, WebView JS-bridge source/sink,
// backup and cleartext-transport controls) rather than re-deriving them, and
// adds two lexical-only checks (insecure storage, signing config) for
// surfaces the extractor does not model.
//
// Every rule states its static/runtime scope, hazards, assumptions, and
// authority limits in `detectorMetadata` so an adjudicator (or a human
// reviewer) never mistakes a lexical/config observation for a device-tested
// or store-reviewed fact. `supportTier` is a frozen constant: detecting a
// manifest/plist/gradle file never raises it — see the specialist-security
// test suite for the assertion that parser presence alone changes nothing.

import { digest } from '../contracts.mjs';

const SUPPORT_TIER = 'measured';

const STANDARD_SCOPE = Object.freeze({
  static: true,
  runtime: false,
  description: 'Repository manifest/config/source text only; no device, emulator, simulator, or app-store connection was made.',
});

const STANDARD_AUTHORITY_LIMITS = Object.freeze([
  'This lens does not establish app-store review outcomes, platform security posture, or regulatory adequacy for any standard.',
  'A finding here is an allegation requiring independent adjudication; it is never a substitute for a qualified mobile security reviewer decision.',
]);

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function safeReadFile(context, file) {
  if (!file || !context.files.includes(file)) return null;
  return context.readFile(file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function withMetadata(base, hazards, assumptions) {
  return {
    ...base,
    scope: STANDARD_SCOPE,
    hazards,
    assumptions,
    authorityLimits: STANDARD_AUTHORITY_LIMITS,
  };
}

const DANGEROUS_ANDROID_PERMISSIONS = new Set([
  'android.permission.CAMERA',
  'android.permission.RECORD_AUDIO',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.ACCESS_BACKGROUND_LOCATION',
  'android.permission.READ_CONTACTS',
  'android.permission.WRITE_CONTACTS',
  'android.permission.READ_SMS',
  'android.permission.SEND_SMS',
  'android.permission.READ_CALL_LOG',
  'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.BODY_SENSORS',
  'android.permission.READ_PHONE_STATE',
]);

const STRIPPED_PERMISSION_PATTERN = /tools:node\s*=\s*"remove"/i;
const AUTO_VERIFY_PATTERN = /android:autoVerify\s*=\s*"true"|applinks:/i;
const PERMISSION_GATE_PATTERN = /android:permission\s*=/i;
const BRIDGE_ORIGIN_ALLOWLIST_PATTERN = /shouldOverrideUrlLoading|originWhitelist|allowlist|allowedOrigins/i;
const SENSITIVE_STORAGE_SINK_PATTERN = /\b(?:SharedPreferences|getSharedPreferences|NSUserDefaults|UserDefaults\.standard|localStorage\.setItem|AsyncStorage\.setItem)\b/g;
const SENSITIVE_VALUE_KEYWORD_PATTERN = /password|passwd|secret|token|apikey|api_key|ssn|creditcard|credit_card|auth[_-]?key/i;
const SECURE_STORAGE_MITIGATION_PATTERN = /EncryptedSharedPreferences|Keychain|SecureStore|expo-secure-store|react-native-keychain|CryptoKit/i;
const GRADLE_FILE_PATTERN = /\.gradle(\.kts)?$/i;
const RELEASE_BLOCK_PATTERN = /release\s*\{[^}]*\}/gi;
const DEBUG_SIGNING_IN_RELEASE_PATTERN = /signingConfig\s+signingConfigs\.debug/i;

function scanWindow(pattern, text, index, length, radius = 400) {
  if (!pattern) return false;
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  return pattern.test(text.slice(start, end));
}

const RULE_IDS = [
  'mobile.permission.dangerous-declared',
  'mobile.deep-link.entrypoint-unvalidated',
  'mobile.exported-component.no-permission-gate',
  'mobile.webview.js-bridge-exposed',
  'mobile.storage.insecure-sensitive-data',
  'mobile.backup.enabled-without-exclusion',
  'mobile.transport.cleartext-allowed',
  'mobile.signing.debug-config-in-release',
];

function analyzePermissions(context, observations) {
  for (const entity of context.model.entities) {
    if (entity.kind !== 'permission-scope') continue;
    const permission = entity.attributes?.permission;
    if (!DANGEROUS_ANDROID_PERMISSIONS.has(permission)) continue;
    const file = entity.attributes?.file;
    const text = safeReadFile(context, file);
    const uncertainty = ['Manifest declaration is not automatically a privacy risk; the runtime rationale/consent flow must be adjudicated.'];
    if (text && STRIPPED_PERMISSION_PATTERN.test(text)) {
      uncertainty.push('A manifest-merger `tools:node="remove"` directive is present near this permission; treated as a mitigating signal pending adjudication.');
      continue;
    }
    observations.push({
      ruleId: 'mobile.permission.dangerous-declared',
      candidateClass: 'mobile',
      claim: `A dangerous Android permission (${permission}) is declared without a visible manifest-level exclusion.`,
      severityHint: 'medium',
      sources: [], sinks: [entity.id],
      attackerCapabilities: ['install-malicious-app', 'trick-user-into-granting-permission'],
      preconditions: [{
        kind: 'principal-access', subject: 'actor:external', action: 'induce-grant',
        object: entity.id, scope: 'mobile', environment: 'mobile', tenant: null,
      }],
      effects: [{
        kind: 'data-access', subject: 'actor:external', action: 'access',
        object: entity.id, scope: 'device-permission', environment: 'mobile', tenant: null,
      }],
      assets: [entity.id], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
      chainRoles: ['enabler'],
      evidenceRefs: entity.evidenceRefs,
      detectorMetadata: withMetadata(
        { file, permission },
        [`Unbounded access to a dangerous device capability (${permission}) if the app is compromised, socially engineered, or over-scoped.`],
        ['The manifest declaration reflects the requested scope; whether the app actually uses the capability minimally is not observed here.'],
      ),
      uncertainty,
    });
  }
}

function analyzeDeepLinks(context, observations) {
  for (const entity of context.model.entities) {
    if (entity.kind !== 'entrypoint' || entity.attributes?.entrypointType !== 'deep-link') continue;
    const file = entity.attributes?.file;
    const text = safeReadFile(context, file);
    let severityHint = 'high';
    const uncertainty = ['A declared deep-link scheme is not automatically exploitable; the handler\'s parameter validation and origin checks must be adjudicated.'];
    if (text && AUTO_VERIFY_PATTERN.test(text)) {
      severityHint = 'medium';
      uncertainty.push('Android App Links `autoVerify`/`applinks:` domain verification is present; downgraded pending adjudication of handler-side validation.');
    }
    observations.push({
      ruleId: 'mobile.deep-link.entrypoint-unvalidated',
      candidateClass: 'mobile',
      claim: 'A deep-link entrypoint is reachable from any installed app or web page without an observed handler-side validation check.',
      severityHint,
      sources: [], sinks: [entity.id],
      attackerCapabilities: ['craft-malicious-deep-link'],
      preconditions: [{
        kind: 'attacker-position', subject: 'actor:external', action: 'reach',
        object: entity.id, scope: 'mobile', environment: 'mobile', tenant: null,
      }],
      effects: [{
        kind: 'workflow-state', subject: 'actor:external', action: 'invoke',
        object: entity.id, scope: 'deep-link-handler', environment: 'mobile', tenant: null,
      }],
      assets: [], trustBoundaryCrossings: [entity.id], requiredControls: [], observedControls: [],
      chainRoles: ['starter'],
      evidenceRefs: entity.evidenceRefs,
      detectorMetadata: withMetadata(
        { file, schemes: entity.attributes?.schemes ?? [] },
        ['A crafted deep link may trigger unintended navigation, parameter injection, or an authenticated action without user intent.'],
        ['App Links domain verification, if present, only proves domain ownership; it does not by itself prove handler-side parameter validation.'],
      ),
      uncertainty,
    });
  }
}

function analyzeExportedComponents(context, observations) {
  for (const entity of context.model.entities) {
    if (entity.kind !== 'entrypoint' || entity.attributes?.entrypointType !== 'exported-component') continue;
    const file = entity.attributes?.file;
    const text = safeReadFile(context, file);
    if (text && PERMISSION_GATE_PATTERN.test(text)) continue;
    observations.push({
      ruleId: 'mobile.exported-component.no-permission-gate',
      candidateClass: 'mobile',
      claim: 'An exported Android component has no visible `android:permission` gate in its declaration file.',
      severityHint: 'high',
      sources: [], sinks: [entity.id],
      attackerCapabilities: ['external-app-launch-component'],
      preconditions: [{
        kind: 'attacker-position', subject: 'actor:external', action: 'launch-component',
        object: entity.id, scope: 'mobile', environment: 'mobile', tenant: null,
      }],
      effects: [{
        kind: 'object-access', subject: 'actor:external', action: 'invoke',
        object: entity.id, scope: 'cross-app', environment: 'mobile', tenant: null,
      }],
      assets: [], trustBoundaryCrossings: [entity.id], requiredControls: [], observedControls: [],
      chainRoles: ['starter'],
      evidenceRefs: entity.evidenceRefs,
      detectorMetadata: withMetadata(
        { file },
        ['Any other installed app can launch this component and reach whatever state or data it exposes.'],
        ['A caller check performed in code rather than the manifest is not observed by this lens.'],
      ),
      uncertainty: ['Caller identity checks implemented in code (rather than the manifest permission attribute) are not visible to this lens.'],
    });
  }
}

function analyzeWebviewBridge(context, observations) {
  for (const relation of context.model.relations) {
    if (relation.kind !== 'calls') continue;
    const source = context.entityById.get(relation.from);
    const sink = context.entityById.get(relation.to);
    if (source?.kind !== 'source' || source.attributes?.sourceKind !== 'webview-js') continue;
    if (sink?.kind !== 'sink' || sink.attributes?.sinkKind !== 'native-bridge') continue;
    const file = source.attributes?.file ?? sink.attributes?.file;
    const text = safeReadFile(context, file);
    let severityHint = 'high';
    const uncertainty = ['A JS-to-native bridge is not automatically exploitable; whether web content is attacker-controllable and which bridge methods are exposed must be adjudicated.'];
    if (text && BRIDGE_ORIGIN_ALLOWLIST_PATTERN.test(text)) {
      severityHint = 'medium';
      uncertainty.push('An origin/URL allowlist check is present in the same file; downgraded pending adjudication of allowlist completeness.');
    }
    observations.push({
      ruleId: 'mobile.webview.js-bridge-exposed',
      candidateClass: 'mobile',
      claim: 'A WebView exposes a JavaScript-to-native bridge without an observed origin allowlist in the same file.',
      severityHint,
      sources: [source.id], sinks: [sink.id],
      attackerCapabilities: ['control-webview-content'],
      preconditions: [{
        kind: 'attacker-position', subject: 'actor:external', action: 'control-webview-content',
        object: source.id, scope: 'mobile', environment: 'mobile', tenant: null,
      }],
      effects: [{
        kind: 'code-execution', subject: 'actor:external', action: 'invoke',
        object: sink.id, scope: 'native-bridge', environment: 'mobile', tenant: null,
      }],
      assets: [], trustBoundaryCrossings: [source.id], requiredControls: [], observedControls: [],
      chainRoles: ['enabler', 'impact'],
      evidenceRefs: [...new Set([...source.evidenceRefs, ...sink.evidenceRefs])].sort(),
      detectorMetadata: withMetadata(
        { file },
        ['Malicious or compromised web content loaded in the WebView may invoke native-bridge methods with attacker-chosen arguments.'],
        ['Per-method argument validation inside the bridge handler is not observed by this lens.'],
      ),
      uncertainty,
    });
  }
}

function analyzeStorage(context, observations) {
  for (const file of context.files) {
    const text = context.readFile(file) ?? '';
    if (!text) continue;
    SENSITIVE_STORAGE_SINK_PATTERN.lastIndex = 0;
    let match;
    while ((match = SENSITIVE_STORAGE_SINK_PATTERN.exec(text)) !== null) {
      if (match[0].length === 0) { SENSITIVE_STORAGE_SINK_PATTERN.lastIndex += 1; continue; }
      if (!scanWindow(SENSITIVE_VALUE_KEYWORD_PATTERN, text, match.index, match[0].length)) continue;
      if (scanWindow(SECURE_STORAGE_MITIGATION_PATTERN, text, match.index, match[0].length)) continue;
      const artifact = findArtifact(context, file);
      observations.push({
        ruleId: 'mobile.storage.insecure-sensitive-data',
        candidateClass: 'mobile',
        claim: 'A sensitive-looking value is written to an unencrypted platform storage API.',
        severityHint: 'high',
        sources: artifact ? [artifact.id] : [], sinks: artifact ? [artifact.id] : [],
        attackerCapabilities: ['local-device-access', 'backup-extraction'],
        preconditions: [{
          kind: 'attacker-position', subject: 'actor:external', action: 'obtain-device-or-backup-access',
          scope: 'mobile', environment: 'mobile', tenant: null,
        }],
        effects: [{
          kind: 'confidentiality-impact', subject: 'actor:external', action: 'read',
          object: artifact?.id ?? null, scope: 'unencrypted-local-storage', environment: 'mobile', tenant: null,
        }],
        assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
        chainRoles: ['starter', 'impact'],
        evidenceRefs: artifact?.evidenceRefs ?? [],
        detectorMetadata: withMetadata(
          { file, line: lineOf(text, match.index), storageApi: match[0] },
          ['A sensitive value stored in cleartext platform storage is recoverable from device backups, rooted/jailbroken access, or another app on older platform versions.'],
          ['Field-level identification of "sensitive" is a keyword heuristic; whether the actual value is genuinely sensitive must be adjudicated.'],
        ),
        uncertainty: ['A keyword co-occurrence match is not automatic proof of sensitive-data storage; the actual value and platform-level sandboxing must be adjudicated.'],
      });
    }
  }
}

function analyzeBackup(context, observations) {
  for (const entity of context.model.entities) {
    if (entity.kind !== 'control' || entity.attributes?.controlType !== 'data-backup') continue;
    if (entity.attributes?.controlState !== 'absent') continue;
    observations.push({
      ruleId: 'mobile.backup.enabled-without-exclusion',
      candidateClass: 'mobile',
      claim: 'Application data backup is enabled with no observed per-file backup exclusion.',
      severityHint: 'medium',
      sources: [], sinks: [entity.id],
      attackerCapabilities: ['obtain-device-or-cloud-backup-access'],
      preconditions: [{
        kind: 'attacker-position', subject: 'actor:external', action: 'obtain-backup-access',
        scope: 'mobile', environment: 'mobile', tenant: null,
      }],
      effects: [{
        kind: 'confidentiality-impact', subject: 'actor:external', action: 'read',
        object: entity.id, scope: 'application-backup', environment: 'mobile', tenant: null,
      }],
      assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
      chainRoles: ['starter', 'impact'],
      evidenceRefs: entity.evidenceRefs,
      detectorMetadata: withMetadata(
        { file: entity.attributes?.file },
        ['Application data, including any locally cached secrets, may be extracted from an ADB or cloud backup.'],
        ['A backup-rules XML that selectively excludes sensitive files/paths is not observed by this lens.'],
      ),
      uncertainty: ['A backup-rules exclusion file may exist elsewhere in the denominator; only the top-level allowBackup flag was observed.'],
    });
  }
}

function analyzeTransport(context, observations) {
  for (const entity of context.model.entities) {
    if (entity.kind !== 'control' || entity.attributes?.controlType !== 'transport-security') continue;
    if (entity.attributes?.controlState !== 'absent') continue;
    observations.push({
      ruleId: 'mobile.transport.cleartext-allowed',
      candidateClass: 'mobile',
      claim: 'The application is explicitly configured to allow cleartext (unencrypted) network traffic.',
      severityHint: 'high',
      sources: [], sinks: [entity.id],
      attackerCapabilities: ['on-path-network-position'],
      preconditions: [{
        kind: 'network-reachability', subject: 'actor:external', action: 'intercept',
        object: entity.id, scope: 'mobile', environment: 'mobile', tenant: null,
      }],
      effects: [{
        kind: 'confidentiality-impact', subject: 'actor:external', action: 'intercept',
        object: entity.id, scope: 'network-traffic', environment: 'mobile', tenant: null,
      }],
      assets: [], trustBoundaryCrossings: [entity.id], requiredControls: [], observedControls: [],
      chainRoles: ['starter', 'impact'],
      evidenceRefs: entity.evidenceRefs,
      detectorMetadata: withMetadata(
        { file: entity.attributes?.file },
        ['A network attacker in the same trust domain (public Wi-Fi, compromised router) can read or tamper with any cleartext traffic.'],
        ['A per-domain network-security-config exception may still exist and narrow this to specific hosts; that granularity is not observed here.'],
      ),
      uncertainty: ['Whether every network call actually traverses TLS regardless of this flag is not confirmed by this lens.'],
    });
  }
}

function analyzeSigning(context, observations) {
  for (const file of context.files) {
    if (!GRADLE_FILE_PATTERN.test(file)) continue;
    const text = context.readFile(file) ?? '';
    if (!text) continue;
    RELEASE_BLOCK_PATTERN.lastIndex = 0;
    let match;
    while ((match = RELEASE_BLOCK_PATTERN.exec(text)) !== null) {
      if (match[0].length === 0) { RELEASE_BLOCK_PATTERN.lastIndex += 1; continue; }
      if (!DEBUG_SIGNING_IN_RELEASE_PATTERN.test(match[0])) continue;
      const artifact = findArtifact(context, file);
      observations.push({
        ruleId: 'mobile.signing.debug-config-in-release',
        candidateClass: 'mobile',
        claim: 'The release build type is signed with the debug signing config.',
        severityHint: 'critical',
        sources: artifact ? [artifact.id] : [], sinks: artifact ? [artifact.id] : [],
        attackerCapabilities: ['forge-app-update', 'impersonate-publisher'],
        preconditions: [{
          kind: 'attacker-position', subject: 'actor:external', action: 'obtain-shared-debug-key',
          scope: 'mobile', environment: 'mobile', tenant: null,
        }],
        effects: [{
          kind: 'integrity-impact', subject: 'actor:external', action: 'forge',
          object: artifact?.id ?? null, scope: 'app-signing', environment: 'mobile', tenant: null,
        }],
        assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
        chainRoles: ['enabler', 'impact'],
        evidenceRefs: artifact?.evidenceRefs ?? [],
        detectorMetadata: withMetadata(
          { file, line: lineOf(text, match.index) },
          ['A release build signed with a widely-shared debug key cannot be trusted to originate from the legitimate publisher.'],
          ['This match is confined to the `release { }` block text captured by a brace-balanced-ish regex; a build script that assembles the config indirectly is not observed by this lens.'],
        ),
        uncertainty: ['Whether this Gradle module actually ships to a store/production channel is not confirmed by this lens.'],
      });
    }
  }
}

export default Object.freeze({
  id: 'security.mobile',
  version: '2.0.0',
  candidateClass: 'mobile',
  description: 'Android/iOS/mobile-framework manifest, config, and source text: permissions, deep links, exported components, WebView bridges, storage, backup, transport, and signing.',
  supportTier: SUPPORT_TIER,
  rules: RULE_IDS.map((id) => ({ id })),
  analyze(context) {
    const observations = [];
    analyzePermissions(context, observations);
    analyzeDeepLinks(context, observations);
    analyzeExportedComponents(context, observations);
    analyzeWebviewBridge(context, observations);
    analyzeStorage(context, observations);
    analyzeBackup(context, observations);
    analyzeTransport(context, observations);
    analyzeSigning(context, observations);
    return observations;
  },
  variantStrategies: Object.fromEntries(RULE_IDS.map((id) => [id, {
    rootCause(candidate) {
      return {
        class: `${id}-observation`,
        semanticFeatures: ['mobile', id, digest(candidate.detectorMetadata?.file ?? id)],
      };
    },
    enumerate(context) {
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${id}-search`, kind: 'model-and-lexical-fallback',
          description: `Enumerate every ${id} observation across the denominator and the mobile surface model.`,
          queryDigest: digest(id), complete: true, coverageGaps: [],
        }],
        matches: [],
        coverageGaps: [],
      };
    },
  }])),
});
