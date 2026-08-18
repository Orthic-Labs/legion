// Embedded/IoT security pack (B7-020). Firmware and embedded source/config
// text only — no device flash, no serial/USB connection, no radio, no
// network probe of any kind. Every rule is a lexical (pattern-only)
// detector that never certifies a device build as safe.

import { digest } from '../contracts.mjs';

const SUPPORT_TIER = 'measured';

const STANDARD_SCOPE = Object.freeze({
  static: true,
  runtime: false,
  description: 'Firmware/embedded source and build-config text only; no device, serial/USB, JTAG, or radio connection was made.',
});

const STANDARD_AUTHORITY_LIMITS = Object.freeze([
  'This lens does not establish device safety, firmware integrity at the flashed binary, or regulatory adequacy for any standard.',
  'A finding here is an allegation requiring independent adjudication against the actual build/flash pipeline; it is never a substitute for a qualified embedded-security reviewer decision.',
]);

function findArtifact(context, file) {
  return context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes?.path === file);
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function windowAround(text, index, length, radius) {
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + length + radius);
  return text.slice(start, end);
}

function withMetadata(base, hazards, assumptions) {
  return { ...base, scope: STANDARD_SCOPE, hazards, assumptions, authorityLimits: STANDARD_AUTHORITY_LIMITS };
}

const RULES = [
  {
    id: 'embedded-iot.firmware.update-without-signature-verification',
    severityHint: 'critical',
    claim: 'A firmware/OTA update path downloads or applies an image with no visible signature or digest verification.',
    pattern: /(?:firmware|_ota_|ota[A-Z_]|fw_image|flash_image)[\s\S]{0,200}?(?:download|apply|write|flash)/gi,
    suppressWindowPattern: /verify|signature|signed|digest|sha256|hmac|secureboot|secure_boot/i,
    suppressScope: 'wide',
    hazards: ['A network- or supply-chain-positioned attacker can push an unsigned malicious firmware image that the device will accept and execute.'],
    assumptions: ['Verification performed by a separate bootloader stage not visible in this source window is not detected and must be adjudicated against the actual boot chain.'],
    effectKind: 'code-execution', effectAction: 'flash-unverified-image', effectScope: 'firmware-update',
    chainRoles: ['starter', 'impact'],
  },
  {
    id: 'embedded-iot.debug-interface.enabled-in-production-build',
    severityHint: 'high',
    claim: 'A debug shell, UART console, or JTAG/SWD interface is enabled with no visible release-build guard.',
    pattern: /#define\s+(?:DEBUG_SHELL_ENABLED|DEBUG_UART_ENABLED|CONFIG_DEBUG_UART|ENABLE_JTAG|ENABLE_SWD)\s+1|debug[_-]?shell\s*[:=]\s*(?:true|enabled|1)/gi,
    suppressWindowPattern: /#ifndef\s+NDEBUG|#if\s+defined\s*\(\s*DEBUG\s*\)|#ifdef\s+DEBUG_BUILD|release_build\s*==\s*false/i,
    suppressScope: 'wide',
    hazards: ['Physical or adjacent access to the debug interface can grant a full memory/flash dump, credential extraction, or arbitrary code execution.'],
    assumptions: ['A board-level fuse or jumper that physically disables the interface in production units is not visible in source text and must be adjudicated separately.'],
    effectKind: 'code-execution', effectAction: 'access-debug-interface', effectScope: 'debug-interface',
    chainRoles: ['enabler', 'impact'],
  },
  {
    id: 'embedded-iot.credentials.hardcoded-secret',
    severityHint: 'high',
    claim: 'A credential-shaped literal (password, API key, or Wi-Fi PSK) is hardcoded in firmware source.',
    pattern: /\b(?:char\s*\*?\s*)?(?:wifi_pass|wifi_psk|api_key|device_secret|admin_password|default_password)\s*(?:\[\s*\]\s*)?=\s*"[^"\n]{4,}"/gi,
    suppressWindowPattern: /getenv|from_nvs|from_flash_config|provisioned_at_factory|read_from_secure_element/i,
    suppressScope: 'match',
    hazards: ['A single extracted binary (or the public source itself) discloses a credential shared across every device of this build, enabling fleet-wide compromise.'],
    assumptions: ['A build-time substitution (e.g. a CI secret injected into this literal before compilation) is not visible in source text and must be adjudicated against the build pipeline.'],
    effectKind: 'credential-possession', effectAction: 'extract-hardcoded-credential', effectScope: 'firmware-binary',
    chainRoles: ['starter', 'pivot'],
  },
  {
    id: 'embedded-iot.identity.shared-static-device-key',
    severityHint: 'high',
    claim: 'A device identity/secret constant is referenced with no visible per-device provisioning mechanism in the same file.',
    pattern: /\b(?:DEVICE_SECRET|DEVICE_KEY|SHARED_DEVICE_KEY)\s*"[^"\n]{4,}"/gi,
    suppressWindowPattern: /per[_-]?device|unique[_-]?id|serial[_-]?number|factory[_-]?provision|secure[_-]?element|atecc/i,
    suppressScope: 'wide',
    hazards: ['A key shared identically across every unit lets compromise of one device (or the firmware image) impersonate the entire fleet to backend services.'],
    assumptions: ['Per-device provisioning performed by a separate factory-programming step not represented in source text is not detected and must be adjudicated against the manufacturing pipeline.'],
    effectKind: 'principal-access', effectAction: 'impersonate-device-fleet', effectScope: 'device-identity',
    chainRoles: ['starter', 'privilege-escalation'],
  },
];

function buildVariantStrategy(rule) {
  return {
    rootCause(candidate) {
      return {
        class: `${rule.id}-observation`,
        semanticFeatures: ['embedded-iot', rule.id, candidate.detectorMetadata?.file ?? rule.id],
      };
    },
    enumerate(context) {
      return {
        denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
        strategies: [{
          id: `${rule.id}-search`, kind: 'lexical-fallback',
          description: `Enumerate every ${rule.id} observation across the denominator.`,
          queryDigest: digest(rule.id), complete: true, coverageGaps: [],
        }],
        matches: [], coverageGaps: [],
      };
    },
  };
}

const FIRMWARE_FILE_PATTERN = /\.(c|h|cpp|hpp|ino|rs)$|(^|\/)(platformio\.ini|CMakeLists\.txt|sdkconfig)$/i;

export default Object.freeze({
  id: 'security.embedded-iot',
  version: '1.0.0',
  candidateClass: 'embedded-iot',
  description: 'Firmware update trust, debug interfaces, hardcoded credentials, and device identity in embedded source/config text.',
  supportTier: SUPPORT_TIER,
  rules: RULES.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      if (!FIRMWARE_FILE_PATTERN.test(file)) continue;
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = findArtifact(context, file);
      for (const rule of RULES) {
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(text)) !== null) {
          if (match[0].length === 0) { rule.pattern.lastIndex += 1; continue; }
          const scope = rule.suppressScope === 'match' ? 0 : rule.suppressScope === 'wide' ? 600 : 250;
          const window = scope === 0 ? match[0] : windowAround(text, match.index, match[0].length, scope);
          if (rule.suppressWindowPattern && rule.suppressWindowPattern.test(window)) continue;

          observations.push({
            ruleId: rule.id,
            candidateClass: 'embedded-iot',
            claim: rule.claim,
            severityHint: rule.severityHint,
            sources: [], sinks: artifact ? [artifact.id] : [],
            attackerCapabilities: ['physical-device-access', 'network-position-to-update-channel', 'firmware-image-extraction'],
            preconditions: [{
              kind: 'attacker-position', subject: 'actor:external', action: 'obtain-device-or-image-access',
              scope: null, environment: 'embedded', tenant: null,
            }],
            effects: [{
              kind: rule.effectKind, subject: 'actor:external', action: rule.effectAction,
              object: artifact?.id ?? null, scope: rule.effectScope, environment: 'embedded', tenant: null,
            }],
            assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
            chainRoles: rule.chainRoles,
            evidenceRefs: artifact?.evidenceRefs ?? [],
            detectorMetadata: withMetadata(
              { file, line: lineOf(text, match.index), matchDigest: digest(match[0]) },
              rule.hazards,
              rule.assumptions,
            ),
            uncertainty: [
              'Lexical pattern match only; not confirmed by binary/flash extraction, a hardware trace, or a device-level test.',
              'Whether this build configuration ever ships to a production unit must be adjudicated independently.',
            ],
          });
        }
      }
    }
    return observations;
  },
  variantStrategies: Object.fromEntries(RULES.map((rule) => [rule.id, buildVariantStrategy(rule)])),
});
