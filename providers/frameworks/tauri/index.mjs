// Tauri framework pack: command contract mirroring, capability scopes,
// window/webview restrictions, updater/signature/transport, sidecars,
// shell/process/http/fs grants, and frontend/native boundary. Tauri v2
// configs and capability files are the fixture matrix.

export default Object.freeze({
  id: 'framework.tauri',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.files ?? []).some((file) => /tauri\.conf\.(json|json5)$|Tauri\.toml$/.test(file));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/dangerousInsecureTransportProtocol["']?\s*[:=]\s*true/.test(text)) {
        observations.push({ ruleId: 'tauri.updater.insecure-transport', severityHint: 'high', claim: 'Updater permits insecure transport.', file });
      }
      if (/devUrl["']?\s*[:=]\s*["'](?!https?:)/.test(text)) {
        observations.push({ ruleId: 'tauri.window.non-http-dev-url', severityHint: 'medium', claim: 'Dev URL is not http(s).', file });
      }
      if (/"shell"\s*:\s*\{\s*"open"\s*:\s*true/.test(text)) {
        observations.push({ ruleId: 'tauri.shell.open-all', severityHint: 'medium', claim: 'shell.open is broadly enabled.', file });
      }
      // Capability file: fs scope with broad read.
      if (/(?:capabilities?\/|capabilities?\.json)/.test(file) && /"fs"\s*:\s*\{[\s\S]{0,300}"scope"\s*:\s*\["\*\*"/.test(text)) {
        observations.push({ ruleId: 'tauri.fs.broad-scope', severityHint: 'medium', claim: 'Filesystem scope is broadly permissive.', file });
      }
      // Sidecar execution from config.
      if (/"sidecar"\s*:\s*true/.test(text)) {
        observations.push({ ruleId: 'tauri.sidecar-enabled', severityHint: 'low', claim: 'Sidecar binary execution is enabled.', file });
      }
      // Updater without signature verification.
      if (/updater["']?\s*[:=]/.test(text) && !/pubkey|signature|key/.test(text)) {
        observations.push({ ruleId: 'tauri.updater.no-signature', severityHint: 'high', claim: 'Updater has no visible signature verification.', file });
      }
    }
    return observations;
  },
});
