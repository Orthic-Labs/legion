// Project-executing provider gate per SNIP-SANDBOX-01: providers that execute
// project code require an externally established network-sandbox receipt.
// Environment variables alone are defense in depth, never the gate.

export class ProviderBlockedError extends Error {
  constructor(provider, reason) {
    super(`provider ${provider} blocked: ${reason}`);
    this.name = 'ProviderBlockedError';
    this.code = 'PROVIDER_BLOCKED';
    this.provider = provider;
    this.reason = reason;
  }
}

export function requireProjectExecutionSandbox(provider, host) {
  if (!provider.hostCapabilities?.includes('project-execution')) return;
  if (host.capabilities.networkSandbox?.active !== true
      || !host.capabilities.networkSandbox?.receipt) {
    throw new ProviderBlockedError(provider.id, 'network-sandbox-receipt-missing');
  }
}
