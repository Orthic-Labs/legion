import { digestValue } from './canonical.mjs';

const ITEM_FIELDS = [
  'acceptance_id', 'id', 'disposition', 'source', 'requirement', 'outcome',
  'source_files', 'owner', 'producer', 'dependencies',
  'observable_acceptance_surface', 'observable_surface', 'observable_exit',
  'positive_test', 'negative_test', 'evidence_producer', 'exclusions',
  'adoption_stage', 'verification_method', 'revisit_trigger',
];

const pick = (value, fields) => Object.fromEntries(
  fields.filter((field) => value[field] !== undefined).map((field) => [field, value[field]]),
);

const itemId = (item) => item.acceptance_id ?? item.id;

export function fingerprintAcceptanceItem(item) {
  if (!itemId(item)) throw new Error('acceptance item requires acceptance_id or id');
  return digestValue(pick(item, ITEM_FIELDS));
}

export function fingerprintAcceptanceStage(stage) {
  if (!stage.stage_id) throw new Error('acceptance stage requires stage_id');
  return digestValue({
    stage_id: stage.stage_id,
    owner: stage.owner,
    dependencies: stage.dependencies ?? [],
    required_items: (stage.required_items ?? []).map((item) => ({
      acceptance_id: itemId(item),
      contract_fingerprint: fingerprintAcceptanceItem(item),
    })),
  });
}

export function fingerprintExecutionSchedule(schedule) {
  return digestValue({
    schedule_version: schedule.schedule_version,
    waves: schedule.waves,
  });
}

export function compileScopedAcceptance(stages, schedule) {
  const stageFingerprints = Object.fromEntries(stages.map((stage) => [
    stage.stage_id,
    fingerprintAcceptanceStage(stage),
  ]));
  return Object.freeze({
    stageFingerprints: Object.freeze(stageFingerprints),
    acceptanceManifestFingerprint: digestValue(stageFingerprints),
    scheduleFingerprint: fingerprintExecutionSchedule(schedule),
  });
}

function descendants(stages, changedIds) {
  const affected = new Set(changedIds);
  let grew = true;
  while (grew) {
    grew = false;
    for (const stage of stages) {
      if (!affected.has(stage.stage_id) && (stage.dependencies ?? []).some((id) => affected.has(id))) {
        affected.add(stage.stage_id);
        grew = true;
      }
    }
  }
  return affected;
}

export function diffScopedAcceptance(previous, next) {
  const before = compileScopedAcceptance(previous.stages, previous.schedule);
  const after = compileScopedAcceptance(next.stages, next.schedule);
  const allIds = new Set([...Object.keys(before.stageFingerprints), ...Object.keys(after.stageFingerprints)]);
  const directlyChangedStageIds = [...allIds].filter(
    (id) => before.stageFingerprints[id] !== after.stageFingerprints[id],
  );
  const invalidatedStageIds = [...new Set([
    ...descendants(previous.stages, directlyChangedStageIds),
    ...descendants(next.stages, directlyChangedStageIds),
  ])].sort();
  return Object.freeze({
    scheduleChanged: before.scheduleFingerprint !== after.scheduleFingerprint,
    acceptanceChanged: directlyChangedStageIds.length > 0,
    directlyChangedStageIds: Object.freeze(directlyChangedStageIds.sort()),
    invalidatedStageIds: Object.freeze(invalidatedStageIds),
    preservedStageIds: Object.freeze([...allIds].filter((id) => !invalidatedStageIds.includes(id)).sort()),
    before,
    after,
  });
}
