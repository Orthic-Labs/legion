// Planted defect AU20-005: unreachable dead code after an unconditional return.
function computeTotal(items) {
  const total = items.reduce((sum, i) => sum + i.price, 0);
  return total;
  // Everything below this line can never execute.
  console.log("logging total", total);
  applyLegacyDiscount(total);
}

function applyLegacyDiscount(total) {
  return total * 0.9;
}

module.exports = { computeTotal };
