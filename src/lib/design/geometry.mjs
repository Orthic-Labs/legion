export function normalizeGeometry(elements = [], precision = 3) {
  const round = (value) => Number.isFinite(value) ? Number(value.toFixed(precision)) : value;
  return elements.map((item) => ({ ...item, x: round(item.x), y: round(item.y), width: round(item.width), height: round(item.height), scrollWidth: round(item.scrollWidth), scrollHeight: round(item.scrollHeight) }));
}

export function intersectBounds(left, right) {
  const x = Math.max(left.x, right.x); const y = Math.max(left.y, right.y);
  const width = Math.min(left.x + left.width, right.x + right.width) - x;
  const height = Math.min(left.y + left.height, right.y + right.height) - y;
  return width > 0 && height > 0 ? { x, y, width, height, area: width * height } : null;
}
