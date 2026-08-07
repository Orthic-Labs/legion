const MAP = { browser: 'browser', nativeSurface: 'native-surface', mobileDevice: 'physical-device', externalEvidence: 'external-evidence', signing: 'signing', reviewing: 'reviewer' };
export function evidenceCapabilities(host = {}) { return Object.entries(MAP).map(([hostKey, id]) => ({ id, available: Boolean(host.capabilities?.[hostKey]), owner: 'host' })); }
