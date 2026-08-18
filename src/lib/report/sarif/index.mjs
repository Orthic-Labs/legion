// Canonical SARIF projection delegates to existing deterministic renderer.
import { reportToSarif } from '../../../../scripts/report-to-sarif.mjs';

export function renderSarifReport(report) {
  return reportToSarif(report);
}
