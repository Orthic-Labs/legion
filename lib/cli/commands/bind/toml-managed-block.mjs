// Stdlib-only TOML managed-block helpers used by the codex harness writer.
// Line-oriented surgery on a small, fixed schema. No TOML parser dependency.

const HEADER_PREFIX = '# >>> legion:managed-block v1 >>>';
const HEADER_SUFFIX = '# <<< legion:managed-block v1 <<<';

export function tomlEscapeBasic(value) {
  let out = '';
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    const code = value.charCodeAt(i);
    if (ch === '\\') out += '\\\\';
    else if (ch === '"') out += '\\"';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\t') out += '\\t';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\f') out += '\\f';
    else if (ch === '\r') out += '\\r';
    else if (code < 0x20 || code === 0x7f) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out;
}

export function tomlBasicString(value) { return '"' + tomlEscapeBasic(value) + '"'; }

export function managedBlock(innerToml) {
  const trimmed = innerToml.replace(/^\n+|\n+$/g, '');
  return HEADER_PREFIX + '\n' + trimmed + '\n' + HEADER_SUFFIX;
}

export function managedBlockDocument(generatedHeader, innerToml) {
  const trimmed = innerToml.replace(/^\n+|\n+$/g, '');
  return generatedHeader + '\n' + managedBlock(trimmed) + '\n';
}

export function hasManagedMarker(existing) {
  return existing.includes(HEADER_PREFIX) && existing.includes(HEADER_SUFFIX);
}

export function extractManagedBlock(existing) {
  const start = existing.indexOf(HEADER_PREFIX);
  if (start < 0) return null;
  const end = existing.indexOf(HEADER_SUFFIX, start);
  if (end < 0) return null;
  return existing.slice(start, end + HEADER_SUFFIX.length);
}

export function parseTableHeaders(text) {
  const headers = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trimStart();
    if (!trimmed.startsWith('[')) continue;
    const close = trimmed.indexOf(']');
    if (close <= 0) continue;
    headers.push(trimmed.slice(0, close + 1));
  }
  return headers;
}

// Extract the body of every owned table from the given text. Returns an
// ordered array of { header, body } where body spans from the header line
// up to (but not including) the next `[` header line. The output preserves
// the original whitespace inside each body. Tables that aren't in
// `LEGION_OWNED_HEADERS` are not returned — the caller treats them as
// unknown and never overwrites them.
export function extractOwnedTables(text, owned) {
  const lines = text.split(/\r?\n/);
  const result = [];
  let current = null;
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trimStart();
    if (trimmed.startsWith('[')) {
      if (current) result.push(current);
      const close = trimmed.indexOf(']');
      const header = close > 0 ? trimmed.slice(0, close + 1) : null;
      current = header && owned.includes(header) ? { header, bodyLines: [] } : null;
    } else if (current) {
      current.bodyLines.push(lines[i]);
    }
  }
  if (current) result.push(current);
  return result;
}

export const LEGION_OWNED_HEADERS = Object.freeze([
  '[agents.sage]', '[agents.alchemist]', '[agents.seer]',
  '[agents.covenant-seat]', '[mcp_servers.legion]',
]);

function isLegionOwned(header) { return LEGION_OWNED_HEADERS.includes(header); }

// Normalize a table-body array into a deterministic string for byte-level
// comparison. Trims trailing whitespace per line and drops trailing blank
// lines so cosmetic whitespace differences don't break adoption.
function normalizeTableBody(bodyLines) {
  let end = bodyLines.length;
  while (end > 0 && bodyLines[end - 1].trim() === '') end--;
  const trimmed = bodyLines.slice(0, end).map((l) => l.replace(/\s+$/, ''));
  return trimmed.join('\n');
}

// Apply the managed block to existing file text:
//   - if no marker is present and the user's file already contains every
//     owned Legion table byte-identical to what we'd generate, adopt it
//     (status `adopted_unchanged`) without writing;
//   - if no marker is present and the user's file contains an owned Legion
//     table that differs from what we'd generate, return `managed_conflict`
//     and never overwrite;
//   - if no marker is present and the user's file has no Legion tables (or
//     only unknown tables), append our managed block (status `written`);
//   - if the marker is present, replace the marker pair in place (status
//     `replaced`) or report `unchanged` when the new block is byte-equal.
export function upsertManagedBlock(existing, generatedHeader, innerToml) {
  const next = managedBlock(innerToml);
  if (!hasManagedMarker(existing)) {
    const existingOwned = extractOwnedTables(existing, LEGION_OWNED_HEADERS);
    const generatedOwned = extractOwnedTables(next, LEGION_OWNED_HEADERS);
    if (existingOwned.length === 0) {
      const document = managedBlockDocument(generatedHeader, innerToml);
      if (!existing) return { status: 'written', content: document };
      return { status: 'written', content: existing + (existing.endsWith('\n') ? '' : '\n') + '\n' + document };
    }
    const existingByHeader = new Map(existingOwned.map((t) => [t.header, t]));
    const generatedByHeader = new Map(generatedOwned.map((t) => [t.header, t]));
    const conflicts = [];
    const unknownHeaders = parseTableHeaders(existing).filter((h) => !isLegionOwned(h));
    let canAdoptIdentical = existingOwned.length === generatedOwned.length && existingOwned.length > 0;
    for (const [header, genTable] of generatedByHeader) {
      const exTable = existingByHeader.get(header);
      if (!exTable) {
        conflicts.push({ header, kind: 'legion_owned_header_missing_in_existing' });
        canAdoptIdentical = false;
        continue;
      }
      const exBody = normalizeTableBody(exTable.bodyLines);
      const genBody = normalizeTableBody(genTable.bodyLines);
      if (exBody !== genBody) {
        conflicts.push({ header, kind: 'legion_owned_header_differs_in_existing', existingBody: exBody, generatedBody: genBody });
        canAdoptIdentical = false;
      }
    }
    for (const header of existingByHeader.keys()) {
      if (!generatedByHeader.has(header)) {
        conflicts.push({ header, kind: 'legion_owned_header_extra_in_existing' });
        canAdoptIdentical = false;
      }
    }
    if (canAdoptIdentical) {
      // Re-emit the file with the marker wrapping the existing tables so
      // future runs can take the marker-present fast path.
      const existingLines = existing.split(/\r?\n/);
      const annotated = annotateExisting(existingLines);
      const document = managedBlockDocument(generatedHeader, innerToml);
      if (!existing || existing.length === 0) return { status: 'written', content: document };
      const sep = existing.endsWith('\n') ? '' : '\n';
      return { status: 'adopted_with_marker', content: `${annotated}${sep}\n${document}` };
    }
    if (conflicts.length > 0) return { status: 'managed_conflict', conflicts };
    const document = managedBlockDocument(generatedHeader, innerToml);
    if (!existing || existing.length === 0) return { status: 'written', content: document };
    const sep = existing.endsWith('\n') ? '' : '\n';
    return { status: 'written', content: existing + sep + '\n' + document };
  }
  const replaced = replaceMarkerPair(existing, next);
  if (replaced === existing) return { status: 'unchanged', content: existing };
  return { status: 'replaced', content: replaced };
}

// Wrap every owned table in the existing user file with the marker pair so
// a fresh `legion bind --write` run after adoption can recognize the
// previously-adopted file as already managed.
function annotateExisting(lines) {
  const out = [];
  let inOwned = false;
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trimStart();
    if (trimmed.startsWith('[')) {
      const close = trimmed.indexOf(']');
      const header = close > 0 ? trimmed.slice(0, close + 1) : null;
      const owned = header && LEGION_OWNED_HEADERS.includes(header);
      if (owned && !inOwned) { out.push(HEADER_PREFIX); inOwned = true; }
      if (!owned && inOwned) { out.push(HEADER_SUFFIX); inOwned = false; }
    }
    out.push(lines[i]);
  }
  if (inOwned) out.push(HEADER_SUFFIX);
  return out.join('\n');
}

function replaceMarkerPair(existing, newBlock) {
  const start = existing.indexOf(HEADER_PREFIX);
  const end = existing.indexOf(HEADER_SUFFIX, start);
  if (start < 0 || end < 0) return existing;
  const endIdx = end + HEADER_SUFFIX.length;
  const trailingMatch = existing.slice(endIdx).match(/^\r?\n/);
  const trailing = trailingMatch ? trailingMatch[0] : '';
  return existing.slice(0, start) + newBlock + trailing + existing.slice(endIdx + trailing.length);
}

export const TOML_MANAGED_MARKER = Object.freeze({ HEADER_PREFIX, HEADER_SUFFIX });
export const LEGION_OWNED_TOML_HEADERS = LEGION_OWNED_HEADERS;
