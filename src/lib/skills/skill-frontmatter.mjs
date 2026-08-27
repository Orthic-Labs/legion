const SCALAR_FIELDS = new Set([
  'name',
  'description',
  'kind',
  'capabilityClass',
  'discoverability',
  'domain',
]);
const LIST_FIELDS = new Set(['operations', 'effects', 'hostRequirements']);
const KINDS = new Set(['capability', 'entrypoint']);
const CAPABILITY_CLASSES = new Set(['domain', 'workflow', 'context']);
const DISCOVERABILITY = new Set(['public', 'explicit', 'internal']);
const DOMAINS = new Set(['engineering', 'research', 'commercial', 'editorial', 'design', 'null']);
const OPERATIONS = new Set(['route', 'analyze', 'diagnose', 'decide', 'produce', 'evaluate', 'execute']);
const EFFECTS = new Set(['source-read', 'artifact-write', 'repository-write', 'process-exec', 'network-request']);

function scalar(value, path, key) {
  const text = value.trim();
  if (!text) return '';
  const quoted = (text.startsWith('"') && text.endsWith('"'))
    || (text.startsWith("'") && text.endsWith("'"));
  if (quoted) return text.slice(1, -1);
  if (/:[ \t]/.test(text)) {
    throw new Error(`${path}: ${key} contains an unquoted YAML mapping delimiter`);
  }
  return text;
}

/** Parse & validate the compact top-level YAML subset used by packaged SKILL.md files. */
export function parseSkillFrontmatter(text, { path = 'SKILL.md' } = {}) {
  if (!text.startsWith('---\n')) throw new Error(`${path}: missing YAML frontmatter opener`);
  const end = text.indexOf('\n---', 4);
  if (end === -1) throw new Error(`${path}: missing YAML frontmatter closer`);
  const lines = text.slice(4, end).split(/\r?\n/);
  const out = {};
  let key = null;
  let block = null;

  const finishBlock = () => {
    if (!block) return;
    out[block.key] = block.lines.join(block.folded ? ' ' : '\n').trim();
    block = null;
  };

  for (const [index, line] of lines.entries()) {
    const top = line.match(/^([A-Za-z_][A-Za-z0-9_-]*):(?:[ \t]*(.*))$/);
    if (top) {
      finishBlock();
      key = top[1];
      const value = top[2];
      if (LIST_FIELDS.has(key)) {
        if (value.trim() && value.trim() !== '[]') {
          throw new Error(`${path}:${index + 2}: ${key} must use a YAML block list or []`);
        }
        out[key] = [];
      } else if (SCALAR_FIELDS.has(key)) {
        if (value.trim() === '>' || value.trim() === '|') {
          block = { key, folded: value.trim() === '>', lines: [] };
        } else {
          out[key] = scalar(value, path, key);
        }
      }
      continue;
    }

    if (block && /^\s+\S/.test(line)) {
      block.lines.push(line.trim());
      continue;
    }
    if (LIST_FIELDS.has(key) && /^\s+-\s+\S/.test(line)) {
      out[key].push(scalar(line.replace(/^\s+-\s+/, ''), path, key));
      continue;
    }
    if (/^\s*$/.test(line) || /^\s+/.test(line)) continue;
    throw new Error(`${path}:${index + 2}: unsupported YAML frontmatter syntax`);
  }
  finishBlock();

  for (const field of ['name', 'description', 'kind', 'discoverability', 'operations', 'effects', 'hostRequirements']) {
    if (!(field in out)) throw new Error(`${path}: missing canonical ${field} metadata`);
  }
  if (out.kind === 'capability' && !out.capabilityClass) {
    throw new Error(`${path}: capability requires capabilityClass`);
  }
  if (!KINDS.has(out.kind)) throw new Error(`${path}: invalid kind ${out.kind}`);
  if (!DISCOVERABILITY.has(out.discoverability)) throw new Error(`${path}: invalid discoverability ${out.discoverability}`);
  if (out.kind === 'capability' && !CAPABILITY_CLASSES.has(out.capabilityClass)) {
    throw new Error(`${path}: invalid capabilityClass ${out.capabilityClass}`);
  }
  if (out.kind === 'entrypoint' && out.capabilityClass) {
    throw new Error(`${path}: entrypoint cannot declare capabilityClass`);
  }
  if (out.domain && !DOMAINS.has(out.domain)) throw new Error(`${path}: invalid optional domain ${out.domain}`);
  for (const [field, vocabulary] of [['operations', OPERATIONS], ['effects', EFFECTS]]) {
    if (new Set(out[field]).size !== out[field].length) throw new Error(`${path}: duplicate ${field} value`);
    for (const value of out[field]) if (!vocabulary.has(value)) throw new Error(`${path}: invalid ${field} value ${value}`);
  }
  if (new Set(out.hostRequirements ?? []).size !== (out.hostRequirements ?? []).length) {
    throw new Error(`${path}: duplicate hostRequirements value`);
  }
  return out;
}
