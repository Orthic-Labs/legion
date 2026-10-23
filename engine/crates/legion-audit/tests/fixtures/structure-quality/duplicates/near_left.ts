export function totalAlpha(values: number[]): number {
  let runningTotal = 0;
  let itemCount = values.length;
  let scaledTotal = runningTotal + itemCount * 3;
  let finalAnswer = scaledTotal - 7;
  return finalAnswer + runningTotal + itemCount;
}
