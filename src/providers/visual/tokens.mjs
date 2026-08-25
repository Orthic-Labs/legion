const TOKEN = /--([\w-]+)\s*:\s*([^;]+);/g;
export function inventoryTokens({ files = [] } = {}) {
  const tokens = []; const seen = new Map();
  for (const file of files) for (const match of file.text.matchAll(TOKEN)) { const item = { name: match[1], value: match[2].trim(), file: file.path }; tokens.push(item); seen.set(`${item.name}\0${item.value}`, [...(seen.get(`${item.name}\0${item.value}`) ?? []), item.file]); }
  const candidates = [...seen.entries()].filter(([, paths]) => paths.length > 1).map(([key, paths]) => ({ ruleId: 'visual.token-duplicate', key, paths }));
  const gaps = files.length ? [] : ['token-files-missing'];
  return { schemaVersion: 1, provider: 'visual.tokens', status: candidates.length ? 'candidates' : gaps.length ? 'unproven' : 'pass', complete: gaps.length === 0,
    denominator: { kind: 'css-token-files', expected: files.length, examined: files.length }, tokens, candidates, coverageGaps: gaps };
}
