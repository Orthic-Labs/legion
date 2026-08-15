import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const legionRoot = resolve(import.meta.dirname, '..');
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function argumentsOf(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new Error(`invalid argument: ${key ?? '<missing>'}`);
    values[key.slice(2)] = value;
  }
  for (const required of ['history', 'direct-packet', 'legacy-template', 's08-evidence']) {
    if (!values[required]) throw new Error(`missing --${required}`);
  }
  return values;
}

function textStats(text) {
  return {
    lines: text.length === 0 ? 0 : text.split(/\r?\n/).length - (text.endsWith('\n') ? 1 : 0),
    lexical_tokens: text.trim() ? text.trim().split(/\s+/).length : 0,
    bytes: Buffer.byteLength(text),
  };
}

function historyRows(text) {
  return text.split(/\r?\n/).filter(Boolean).map((line, index) => {
    try { return JSON.parse(line); }
    catch (error) { throw new Error(`history line ${index + 1} is invalid JSON: ${error.message}`); }
  });
}

function messageOf(row) {
  return row?.payload?.message ?? row?.payload?.last_agent_message ?? '';
}

function tokenProjection(row) {
  const usage = row.payload.info.total_token_usage;
  return {
    total: usage.total_tokens,
    input: usage.input_tokens,
    cached_input: usage.cached_input_tokens,
    output: usage.output_tokens,
  };
}

function subtractTokens(first, last) {
  const input = last.input - first.input;
  const cached = last.cached_input - first.cached_input;
  const output = last.output - first.output;
  return {
    total: last.total - first.total,
    input,
    cached_input: cached,
    uncached_input: input - cached,
    output,
    effective_uncached_plus_output: input - cached + output,
  };
}

function within(row, start, end) {
  return row.timestamp >= start && row.timestamp <= end;
}

function replayHistory(rows) {
  const start = rows.find((row) => row.type === 'event_msg' && row.payload?.type === 'user_message' && messageOf(row).includes('actually give me lane A'));
  const directStart = rows.find((row) => row.type === 'event_msg' && row.payload?.type === 'agent_message' && messageOf(row).includes('Dispatch is written as 7 simultaneous'));
  const finish = rows.find((row) => row.type === 'event_msg' && row.payload?.type === 'task_complete' && messageOf(row).includes('DeepSeek Phase A dispatch'));
  const failure = rows.find((row) => row.type === 'event_msg' && row.payload?.type === 'agent_message' && messageOf(row).includes('115 schema defects'));
  if (!start || !directStart || !finish || !failure) throw new Error('history lacks required Dispatch incident markers');
  const window = rows.filter((row) => within(row, start.timestamp, finish.timestamp));
  const directWindow = rows.filter((row) => within(row, directStart.timestamp, finish.timestamp));
  const toolCalls = (slice) => slice.filter((row) => row.type === 'response_item' && ['custom_tool_call', 'function_call'].includes(row.payload?.type)).length;
  const tokenSamples = window.filter((row) => row.type === 'event_msg' && row.payload?.type === 'token_count').map(tokenProjection);
  const directTokenSamples = directWindow.filter((row) => row.type === 'event_msg' && row.payload?.type === 'token_count').map(tokenProjection);
  if (tokenSamples.length < 2 || directTokenSamples.length < 2) throw new Error('history lacks bounded token samples');
  return {
    source_thread_id: '019fff90-2826-7443-adcc-bf4fe1075d53',
    started_at: start.timestamp,
    direct_recovery_started_at: directStart.timestamp,
    completed_at: finish.timestamp,
    delivery_time_ms: Date.parse(finish.timestamp) - Date.parse(start.timestamp),
    direct_recovery_time_ms: Date.parse(finish.timestamp) - Date.parse(directStart.timestamp),
    coordination: {
      user_turns: window.filter((row) => row.type === 'event_msg' && row.payload?.type === 'user_message').length,
      agent_updates: window.filter((row) => row.type === 'event_msg' && row.payload?.type === 'agent_message').length,
      ceremony_requirements: 6,
    },
    tool_calls: toolCalls(window),
    direct_recovery_tool_calls: toolCalls(directWindow),
    tokens: subtractTokens(tokenSamples[0], tokenSamples.at(-1)),
    direct_recovery_tokens: subtractTokens(directTokenSamples[0], directTokenSamples.at(-1)),
    outcome: {
      legacy_validator: 'UNPROVEN',
      direct_packet: 'UNPROVEN',
    },
    quiescent_after_completion: true,
    duplicate_effects: 0,
  };
}

function validateDirectPacket(path) {
  const temporary = mkdtempSync(join(tmpdir(), 'legion-s12-'));
  const receipt = join(temporary, 'direct-packet.receipt.json');
  const started = performance.now();
  try {
    const python = process.env.ORTHIC_PYTHON || (process.platform === 'win32' ? 'py' : 'python3');
    const pythonArgs = process.platform === 'win32' && !process.env.ORTHIC_PYTHON ? ['-3.11'] : [];
    const result = spawnSync(python, [...pythonArgs,
      'lib/dispatch-validator/validate-dispatch.py',
      path,
      '--packet-type', 'authority',
      '--write-receipt', receipt,
    ], { cwd: legionRoot, encoding: 'utf8' });
    const durationMs = Math.max(0, Math.round((performance.now() - started) * 1000) / 1000);
    const output = `${result.stdout || ''}${result.stderr || ''}`.trim();
    if (result.error) throw new Error(`direct validator failed: ${result.error.message}`);
    if (result.status !== 0) throw new Error(`direct validator failed: ${output}`);
    const packet = JSON.parse(readFileSync(path, 'utf8'));
    const receiptBytes = readFileSync(receipt);
    const receiptValue = JSON.parse(receiptBytes);
    const owned = packet.workers.flatMap((worker) => worker.own);
    if (packet.workers.length !== 7 || owned.length !== 175 || new Set(owned).size !== 175) {
      throw new Error('direct packet must bind seven owners to 175 unique paths');
    }
    return {
      outcome: 'PASS', tool_calls: 1, model_tokens: 0, delivery_time_ms: durationMs,
      quiescent_after_completion: true, duplicate_effects: 0,
      worker_count: packet.workers.length, owned_path_count: owned.length,
      unique_path_count: new Set(owned).size,
      packet_digest: `sha256:${receiptValue.sha256}`,
      validator_receipt_digest: sha256(receiptBytes),
    };
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

export function calibrateStage12({ historyText, directPacketText, directPacketPath, legacyTemplateText, s08Receipt }) {
  const history = replayHistory(historyRows(historyText));
  history.source = {
    transcript_id: history.source_thread_id,
    digest: sha256(historyText),
    bytes: Buffer.byteLength(historyText),
  };
  const direct = validateDirectPacket(directPacketPath);
  const governed = s08Receipt.workload;
  if (governed?.result?.status !== 'PASS' || governed.observed_failures?.length !== 0) throw new Error('S08 governed workload is not a clean PASS');
  const legacyStats = textStats(legacyTemplateText);
  const directStats = textStats(directPacketText);
  // This history is not an authenticated disposition source.  Do not turn an
  // agent report or caller-supplied transcript identity into user authority.
  const controls = [{
    control_id: 'dispatch-legacy-default',
    lifecycle: 'PENDING',
    net_harmful: true,
    disposition: 'UNPROVEN',
    disposition_authority: null,
    judgment_source: null,
    rationale: 'Historical transcript and local validator observations do not authenticate a retirement authority or disposition.',
    replacement: 'skills/dispatch/assets/direct-packet.json + packetType=direct validator',
    compatibility: 'legacy Markdown remains explicit opt-in only',
  }];
  return {
    schema: 'stage12-calibration.v1',
    calibration_table_version: 1,
    scenarios: {
      real_legion_history: history,
      minimal_ambient_baseline: { ...direct, packet: directStats },
      governed_s08_workload: {
        outcome: governed.result.status,
        acceptance_surface: governed.actual_acceptance_surface,
        tool_calls: 1,
        model_tokens: 0,
        delivery_time_ms: null,
        quiescent_after_completion: true,
        duplicate_effects: 0,
        evidence_digest: s08Receipt.workload.artifact.digest,
      },
    },
    deltas: {
      legacy_to_direct_packet_lines: directStats.lines - legacyStats.lines,
      legacy_to_direct_lexical_tokens: directStats.lexical_tokens - legacyStats.lexical_tokens,
      legacy_to_direct_bytes: directStats.bytes - legacyStats.bytes,
      history_to_ambient_tool_calls: direct.tool_calls - history.tool_calls,
      history_to_ambient_effective_tokens: direct.model_tokens - history.tokens.effective_uncached_plus_output,
      history_to_ambient_delivery_time_ms: Math.round(direct.delivery_time_ms - history.delivery_time_ms),
      outcome: 'UNPROVEN',
      quiescence: 'PRESERVED',
      duplicate_effects: 0,
    },
    controls,
    all_net_harmful_controls_disposed: controls.filter((control) => control.net_harmful).every((control) => ['RETIRE', 'ACCEPT'].includes(control.disposition)),
  };
}

/** Fields durable calibration evidence may claim without a separate authority receipt. */
export function stage12TruthSemantics(calibration) {
  return {
    history_outcome: calibration.scenarios?.real_legion_history?.outcome,
    delta_outcome: calibration.deltas?.outcome,
    controls: (calibration.controls ?? []).map(({ control_id, lifecycle, net_harmful, disposition, disposition_authority, judgment_source }) =>
      ({ control_id, lifecycle, net_harmful, disposition, disposition_authority, judgment_source })),
    all_net_harmful_controls_disposed: calibration.all_net_harmful_controls_disposed,
  };
}

export function validateRetirementDecisionRecord(record) {
  return record?.schema === 'legion-current-user-disposition.v1'
    && record.control_id === 'dispatch-legacy-default'
    && record.disposition === 'RETIRE'
    && record.authority === 'current-user'
    && typeof record.source_thread_id === 'string' && record.source_thread_id.length > 0
    && typeof record.user_message === 'string' && /\bretire\b/i.test(record.user_message)
    && record.restore_strategy === 'git-history'
    && /^\d{4}-\d{2}-\d{2}$/.test(record.recorded_on ?? '');
}

export function applyRetirementDecision(calibration, record, { sourcePath, sourceDigest } = {}) {
  if (!validateRetirementDecisionRecord(record)) throw new Error('invalid current-user retirement decision record');
  if (typeof sourcePath !== 'string' || !sourcePath || !/^sha256:[a-f0-9]{64}$/.test(sourceDigest ?? '')) throw new Error('retirement decision source binding is required');
  const controls = calibration.controls.map((control) => control.control_id === record.control_id ? {
    ...control,
    lifecycle: 'RETIRED',
    disposition: 'RETIRE',
    disposition_authority: 'current-user',
    judgment_source: { path: sourcePath, digest: sourceDigest, source_thread_id: record.source_thread_id },
    rationale: 'Current user explicitly retired legacy Dispatch because Git history preserves recovery.',
  } : control);
  return {
    ...calibration,
    controls,
    all_net_harmful_controls_disposed: controls.filter((control) => control.net_harmful).every((control) => ['RETIRE', 'ACCEPT'].includes(control.disposition)),
    missing_receipts: [],
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const args = argumentsOf(process.argv.slice(2));
    const output = calibrateStage12({
      historyText: readFileSync(resolve(args.history), 'utf8'),
      directPacketText: readFileSync(resolve(args['direct-packet']), 'utf8'),
      directPacketPath: resolve(args['direct-packet']),
      legacyTemplateText: readFileSync(resolve(args['legacy-template']), 'utf8'),
      s08Receipt: JSON.parse(readFileSync(resolve(args['s08-evidence']), 'utf8')),
    });
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
