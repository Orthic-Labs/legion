export function sum(values) {
  return values.reduce((a, b) => a + b, 0);
}

export function mean(values) {
  if (values.length === 0) {
    return 0;
  }
  return sum(values) / values.length;
}
