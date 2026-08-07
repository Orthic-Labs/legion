import { createPatternPack } from './pattern-pack.mjs';

export default createPatternPack({ id: 'security.native-workspace', family: 'native-workspace', description: 'Native process, workspace plugin, and updater trust boundaries.', rules: [
  { id: 'native.shell-string-command', pattern: /(?:Command::new\(['"](?:sh|bash|cmd|powershell)|child_process\.exec\s*\(|subprocess\.(?:run|Popen)\([^\n]*shell\s*=\s*True)/i, claim: 'A native process boundary invokes a shell-capable command path.', effectKind: 'code-execution', effectAction: 'execute', severityHint: 'high' },
  { id: 'native.updater-insecure-transport', pattern: /(?:update|download|artifact)[\s\S]{0,180}http:\/\//i, claim: 'A native update or artifact path may use insecure transport.', effectKind: 'code-execution', severityHint: 'high' },
  { id: 'native.plugin-untrusted-path', pattern: /(?:plugin|extension)[\s\S]{0,120}(?:load|import|require)\s*\([^\n]*(?:input|config|env)/i, claim: 'A configurable plugin path may cross into executable loading.', effectKind: 'code-execution' },
] });
