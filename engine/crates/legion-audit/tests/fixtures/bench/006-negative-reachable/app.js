// Negative control AU20-006: looks like it could be dead code (function defined,
// only invoked conditionally) but IS reachable and exported — must NOT be flagged
// as dead/unreachable code.
function applySeasonalDiscount(total, isHoliday) {
  if (isHoliday) {
    return total * 0.8;
  }
  return total;
}

function computeTotal(items, isHoliday) {
  const total = items.reduce((sum, i) => sum + i.price, 0);
  return applySeasonalDiscount(total, isHoliday);
}

module.exports = { computeTotal, applySeasonalDiscount };
