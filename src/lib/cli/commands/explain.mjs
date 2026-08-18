import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { EXIT, LegionError } from '../../errors.mjs';

// PR05: explain resolves a finding/gap ID from a run's report or facts.
// PR36 deepens this with fix guidance and remediation context.
export function runExplain(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { json: { type: 'boolean' }, run: { type: 'string' } },
    strict: true,
  });
  const [id] = parsed.positionals;
  if (!id) throw new LegionError('explain requires a finding or gap id', { code: 'USAGE', exitCode: EXIT.USAGE });
  const runDir = parsed.values.run;
  let source = null;
  if (runDir) {
    const { join } = awaitImportPath();
    const reportPath = join(runDir, 'report.json');
    try {
      source = JSON.parse(readFileSync(reportPath, 'utf8'));
    } catch {
      // facts.json fallback
      const factsPath = join(runDir, 'facts.json');
      source = JSON.parse(readFileSync(factsPath, 'utf8'));
    }
  }
  const findings = source?.findings ?? [];
  const gaps = source?.coverage_gaps ?? [];
  const finding = findings.find((item) => item.id === id || item.ruleId === id);
  const gap = gaps.find((item) => item.kind === id || item.kind === id);
  const explanation = {
    schemaVersion: 1,
    kind: 'legion-explain',
    id,
    found: Boolean(finding || gap),
    finding: finding ?? null,
    gap: gap ?? null,
    detail: finding
      ? `${finding.title ?? finding.ruleId} — ${finding.detail ?? ''} (severity ${finding.severity ?? 'unknown'})`
      : gap
        ? `coverage gap ${gap.kind}: ${JSON.stringify(gap.detail ?? {})}`
        : `no finding or gap with id ${id} in ${runDir ?? 'no run supplied'}`,
  };
  stdout.write(`${JSON.stringify(explanation, null, 2)}\n`);
  return { exitCode: explanation.found ? EXIT.PASS : EXIT.USAGE };
}

function awaitImportPath() {
  return { join: (a, b) => `${a}/${b}` };
}
