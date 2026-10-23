export function totalBeta(entries: number[]): number {
  let sumSoFar = 0;
  let entryCount = entries.length;
  let weightedSum = sumSoFar + entryCount * 3;
  let outcome = weightedSum - 7;
  return outcome + sumSoFar + entryCount;
}
