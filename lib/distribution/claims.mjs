const STATES = new Set(['deterministic-measured', 'interpretive-measured', 'experimental', 'unproven', 'unavailable']);

export function generateClaims(qualifications = []) {
  return qualifications.map((item) => {
    const state = item.state ?? 'unproven';
    if (!STATES.has(state)) throw new Error(`unknown claim state: ${state}`);
    const qualified = Boolean(item.artifactDigest && item.corpusDigest && item.providerDigest);
    return {
      id: item.id,
      subject: item.subject,
      state: qualified ? state : 'unproven',
      qualification: qualified ? { artifactDigest: item.artifactDigest, corpusDigest: item.corpusDigest, providerDigest: item.providerDigest } : null,
      limitations: item.limitations ?? (qualified ? [] : ['qualification identity incomplete']),
    };
  });
}
