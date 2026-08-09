// Organization policy packs per SNIP-POLICY-01. Signed/versioned identity,
// repository overrides bounded by host policy, suppressions/accepted risk, and
// rollout modes (shadow | advisory | blocking).

export function organizationPolicy({ id, version, digest, signature, rollout, requiredProviders, thresholds, suppressionPolicy, complianceMappings }) {
  return {
    schemaVersion: 1,
    kind: 'legion-organization-policy',
    id,
    version,
    digest,
    signature: signature ?? {},
    rollout,
    requiredProviders: [...(requiredProviders ?? [])].sort(),
    thresholds: thresholds ?? {},
    suppressionPolicy: suppressionPolicy ?? {},
    complianceMappings: [...(complianceMappings ?? [])].sort(),
  };
}

export function applyPolicy({ policy, plan, hostPolicy }) {
  // Repository overrides are bounded by host policy.
  const overrides = [];
  if (policy?.rollout === 'blocking') {
    for (const provider of policy.requiredProviders ?? []) {
      if (!(plan?.denominator?.providerIds ?? []).includes(provider)) {
        overrides.push({ kind: 'missing-required-provider', provider });
      }
    }
  }
  // Host policy bounds: repository policy can never require a disabled host provider.
  for (const provider of policy?.requiredProviders ?? []) {
    if ((hostPolicy?.disabledProviders ?? []).includes(provider)) {
      overrides.push({ kind: 'host-bounded-provider', provider });
    }
  }
  return {
    schemaVersion: 1,
    kind: 'legion-org-policy-application',
    policyId: policy?.id ?? null,
    rollout: policy?.rollout ?? 'advisory',
    violations: overrides,
    blocked: (policy?.rollout === 'blocking') && overrides.some((item) => item.kind === 'missing-required-provider'),
  };
}
