import { parseArgs } from 'node:util';
import { readFileSync, writeFileSync } from 'node:fs';
import { EXIT, NemesisError } from '../../errors.mjs';

export async function runReport(argv, { stdout, stderr, cwd }) {
  const parsed = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { format: { type: 'string' }, out: { type: 'string' } },
    strict: false,
  });
  const [reportPath] = parsed.positionals;
  if (!reportPath) throw new NemesisError('report requires a report.json path', { code: 'USAGE', exitCode: EXIT.USAGE });
  const format = parsed.values.format ?? 'json';
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  let output;
  if (format === 'json') {
    output = `${JSON.stringify(report, null, 2)}\n`;
  } else if (format === 'sarif') {
    const { reportToSarif } = await import('../../../scripts/report-to-sarif.mjs');
    output = `${JSON.stringify(reportToSarif(report), null, 2)}\n`;
  } else {
    throw new NemesisError(`unsupported report format: ${format}`, { code: 'USAGE', exitCode: EXIT.USAGE });
  }
  if (parsed.values.out) writeFileSync(parsed.values.out, output);
  else stdout.write(output);
  return { exitCode: EXIT.PASS };
}
