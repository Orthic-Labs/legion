import { targetId } from '../contracts.mjs';
const RULES = [
  ['desktop-app', /tauri\.conf\.json|electron-builder|electron\.js/i], ['ios-app', /\.xcodeproj|Info\.plist/i], ['android-app', /build\.gradle|AndroidManifest\.xml/i],
  ['web-app', /next\.config|vite\.config|react-scripts/i], ['api-service', /fastapi|express|koa|nestjs/i], ['worker', /worker\.(js|ts)|bullmq|celery/i],
  ['cli', /"bin"\s*:/i], ['library-sdk', /"exports"\s*:/i], ['infrastructure', /terraform|cloudformation|pulumi/i], ['documentation-product', /mkdocs|docusaurus/i],
];
function sourceFiles(projection) { return projection.files ?? projection.filePaths ?? projection.manifest?.files ?? []; }
export async function discoverTargets(projection, options = {}) {
  const files = sourceFiles(projection).map((item) => typeof item === 'string' ? item : item.path).filter(Boolean);
  const text = JSON.stringify(projection);
  const results = [];
  for (const [kind, pattern] of RULES) {
    const evidence = files.filter((path) => pattern.test(path)).concat(pattern.test(text) ? ['projection'] : []).filter((value, index, values) => values.indexOf(value) === index);
    if (evidence.length) { const root = evidence[0] === 'projection' ? '.' : evidence[0].split('/').slice(0, -1).join('/') || '.'; results.push({ id: targetId(kind, root, evidence), kind, root, entrypoints: [], buildOutputs: [], confidence: 'high', classificationBasis: 'observed', evidencePaths: evidence, conflicts: [] }); }
  }
  const outputs = projection.buildOutputs ?? [];
  for (const output of outputs) if (!results.some((target) => target.evidencePaths.includes(output.path ?? output))) { const path = output.path ?? output; results.push({ id: targetId('unknown-deliverable', path, [path]), kind: 'unknown-deliverable', root: path, entrypoints: [], buildOutputs: [path], confidence: 'medium', classificationBasis: 'observed', evidencePaths: [path], conflicts: [] }); }
  return results.sort((a, b) => a.id.localeCompare(b.id));
}
