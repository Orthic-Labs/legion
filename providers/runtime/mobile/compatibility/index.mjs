const ACCESSIBILITY_MODES = Object.freeze(['voiceover', 'talkback', 'switch-control', 'voice-control', 'keyboard', 'focus', 'labels-announcements-errors', 'dynamic-type', 'contrast', 'reduced-motion', 'audio-media-alternatives', 'accessibility-automation']);
const PLATFORMS = Object.freeze(['ios', 'android']);

export function compileMobileCompatibility({ criticalJourneys = [], executed = [], supported = {} } = {}) {
  const iosExpected = [
    ...criticalJourneys.flatMap((journeyId) => ACCESSIBILITY_MODES.map((value) => ({ dimension: 'accessibility', value, journeyId, platform: 'ios' }))),
    ...(supported.platforms ?? []).filter((p) => p === 'ios').map((value) => ({ dimension: 'platform', value, platform: 'ios' })),
    ...(supported.devices ?? []).map((value) => ({ dimension: 'device', value, platform: 'ios' })),
    ...(supported.displays ?? []).map((value) => ({ dimension: 'display', value, platform: 'ios' })),
    ...(supported.hardware ?? []).map((value) => ({ dimension: 'hardware', value, platform: 'ios' })),
    ...(supported.locales ?? []).map((value) => ({ dimension: 'locale', value, platform: 'ios' })),
    ...(supported.oemFamilies ?? []).map((value) => ({ dimension: 'oem', value, platform: 'ios' })),
  ];
  const androidExpected = [
    ...criticalJourneys.flatMap((journeyId) => ACCESSIBILITY_MODES.map((value) => ({ dimension: 'accessibility', value, journeyId, platform: 'android' }))),
    ...(supported.platforms ?? []).filter((p) => p === 'android').map((value) => ({ dimension: 'platform', value, platform: 'android' })),
    ...(supported.devices ?? []).map((value) => ({ dimension: 'device', value, platform: 'android' })),
    ...(supported.displays ?? []).map((value) => ({ dimension: 'display', value, platform: 'android' })),
    ...(supported.hardware ?? []).map((value) => ({ dimension: 'hardware', value, platform: 'android' })),
    ...(supported.locales ?? []).map((value) => ({ dimension: 'locale', value, platform: 'android' })),
    ...(supported.oemFamilies ?? []).map((value) => ({ dimension: 'oem', value, platform: 'android' })),
  ];
  const expected = [...iosExpected, ...androidExpected];
  const key = (item) => `${item.platform}:${item.dimension}:${item.value}:${item.journeyId ?? '*'}`;
  const executedKeys = new Set(executed.map((item) => ({ ...item, platform: item.platform ?? (item.dimension === 'platform' && PLATFORMS.includes(item.value) ? item.value : null) })).filter((item) => item.platform).map(key));
  const omitted = expected.filter((item) => !executedKeys.has(key(item))).map((item) => ({ ...item, reason: 'device-evidence-unavailable' }));
  const accounted = (platform, cells) => cells.length - omitted.filter((item) => item.platform === platform).length + omitted.filter((item) => item.platform === platform).length;
  const iosAccounted = accounted('ios', iosExpected);
  const androidAccounted = accounted('android', androidExpected);
  const gaps = criticalJourneys.filter((journeyId) => !executed.some((item) => item.dimension === 'accessibility' && item.journeyId === journeyId && item.status === 'pass')).map((journeyId) => `accessibility-journey-missing:${journeyId}`);
  return { schemaVersion: 1, kind: 'nemesis-mobile-compatibility-matrix', status: omitted.length ? 'partial' : 'pass', terminal: true,
    executed, omitted, denominator: { total: expected.length, accounted: iosAccounted + androidAccounted, ios: { total: iosExpected.length, accounted: iosAccounted }, android: { total: androidExpected.length, accounted: androidAccounted } }, coverageGaps: gaps };
}
