export function reviewClassification(candidates, review = null) {
  if (!review) return { status: candidates.some((candidate) => candidate.kind === 'unknown-deliverable') ? 'unproven' : 'pass', candidates, conflicts: [] };
  return { status: 'unproven', candidates, conflicts: review.conflicts ?? [], review: { nominations: review.nominations ?? [], bounded: true } };
}
