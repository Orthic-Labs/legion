// Planted defect AU20-005 (dead module): nothing in this project imports this
// file, so a dead-code scanner (knip) reports it as an unused file.
function applyLegacyDiscount(total) {
  return total * 0.9;
}

module.exports = { applyLegacyDiscount };
