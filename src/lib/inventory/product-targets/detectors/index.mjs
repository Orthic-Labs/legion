import { targetId } from '../contracts.mjs';
import { digest } from '../../../core/binding.mjs';
export const DETECTOR_RULES = Object.freeze({
  website: /(?:^|\/)(?:public\/)?index\.html$|astro\.config|hugo\.(?:toml|yaml)|_config\.yml/i,
  'web-app': /next\.config|vite\.config|react-scripts|svelte\.config|nuxt\.config/i,
  'api-service': /fastapi|express|koa|nestjs|openapi\.(?:json|ya?ml)|routes?\//i,
  worker: /worker\.(?:js|ts)|bullmq|celery|cloudflare.*worker|wrangler\.toml/i,
  'serverless-function': /serverless\.ya?ml|functions?\/[^/]+\.(?:js|ts|py)|lambda/i,
  'desktop-app': /tauri\.conf\.json|electron-builder|electron\.js|\.csproj.*winexe/i,
  'ios-app': /\.xcodeproj|Info\.plist|Package\.swift/i,
  'android-app': /build\.gradle|AndroidManifest\.xml/i,
  'mobile-extension': /(?:share|notification|widget).*extension|NSExtension/i,
  cli: /"bin"\s*:|(?:^|\/)bin\/[^/]+$|commander|click\.command/i,
  'library-sdk': /"exports"\s*:|(?:^|\/)lib\/index\.|pyproject\.toml|Cargo\.toml/i,
  'browser-extension': /(?:extension|browser-extension)\/manifest\.json|browser\.runtime|chrome\.runtime|"manifest_version"/i,
  'editor-extension': /"engines"\s*:\s*\{[^}]*"vscode"|vscode\.commands|extension\.ts/i,
  'plugin-system': /plugins?\/|plugin-api|registerPlugin/i,
  'data-pipeline': /airflow|dagster|dbt_project|pipelines?\/|etl/i,
  infrastructure: /terraform|cloudformation|pulumi|kustomization|helmfile/i,
  'ai-agent-system': /agents?\/|langchain|autogen|tool_calls?|mcp-server/i,
  'embedded-firmware': /platformio\.ini|\.ino$|zephyr|firmware\/|stm32/i,
  'smart-contract': /\.sol$|hardhat\.config|foundry\.toml|anchor\.toml/i,
  'documentation-product': /mkdocs|docusaurus|docs\/.*\.md$|vitepress/i,
});
function sourceFiles(projection) { return projection.files ?? projection.filePaths ?? projection.manifest?.files ?? []; }
export async function discoverTargets(projection, options = {}) {
  const files = sourceFiles(projection).map((item) => typeof item === 'string' ? item : item.path).filter(Boolean).map((path)=>path.replaceAll('\\','/'));
  const manifests=(Array.isArray(projection.manifests)?projection.manifests:Object.values(projection.manifests??{})).map((manifest)=>({name:manifest?.name,bin:manifest?.bin,exports:manifest?.exports,engines:manifest?.engines,manifest_version:manifest?.manifest_version,background:manifest?.background,permissions:manifest?.permissions,type:manifest?.type}));
  const structuredEvidence = {manifests,dependencies:Object.keys(projection.dependencies??{}),packages:(projection.packages??[]).map((item)=>typeof item==='string'?item:item.name),scripts:Object.keys(projection.scripts??{}),entrypoints:projection.entrypoints,buildOutputs:projection.buildOutputs,deployments:projection.deployments};
  const text = JSON.stringify(structuredEvidence);
  const results = [];
  for (const [kind, pattern] of Object.entries(DETECTOR_RULES)) {
    const evidence = files.filter((path) => pattern.test(path)).concat(pattern.test(text) ? ['projection'] : []).filter((value, index, values) => values.indexOf(value) === index);
    if (evidence.length) { const root = evidence[0] === 'projection' ? '.' : evidence[0].split('/').slice(0, -1).join('/') || '.'; const buildOutputs=(projection.buildOutputs??[]).map((item)=>item.path??item).filter((path)=>String(path).replaceAll('\\','/').startsWith(root==='.'?'':root));const value={ id: targetId(kind, root, evidence), kind, facets:[],root, entrypoints: (projection.entrypoints??[]).map((item)=>item.path??item), buildOutputs, distributions:[],environments:[],componentIds:[],stackIds:[],relations:[],confidence: evidence.includes('projection')&&evidence.length===1?'medium':'high', classificationBasis: 'observed', detectorVersion: '1.0.0', evidencePaths: evidence, conflicts: [],binding:options.binding??null };results.push({...value,digest:digest(value)}); }
  }
  const outputs = projection.buildOutputs ?? [];
  for (const output of outputs) if (!results.some((target) => target.evidencePaths.includes(output.path ?? output))) { const path = output.path ?? output;const value={ id: targetId('unknown-deliverable', path, [path]), kind: 'unknown-deliverable',facets:[], root: path, entrypoints: [], buildOutputs: [path],distributions:[],environments:[],componentIds:[],stackIds:[],relations:[], confidence: 'medium', classificationBasis: 'observed', detectorVersion: '1.0.0', evidencePaths: [path], conflicts: [],binding:options.binding??null };results.push({...value,digest:digest(value)}); }
  return results.sort((a, b) => a.id.localeCompare(b.id));
}
