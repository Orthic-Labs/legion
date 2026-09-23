// Negative control AU20-008: two functions with a similar SHAPE (same
// structure of if-checks) but genuinely different behavior/values — not
// true duplication. Must NOT be flagged as duplicated logic.
function validateShippingAddress(fields) {
  if (!fields.street || fields.street.length < 3) {
    return { ok: false, reason: "invalid_street" };
  }
  if (!fields.zip || !/^\d{5}$/.test(fields.zip)) {
    return { ok: false, reason: "invalid_zip" };
  }
  if (!fields.state) {
    return { ok: false, reason: "missing_state" };
  }
  return { ok: true };
}

function validateBillingAddress(fields) {
  if (!fields.company || fields.company.length < 1) {
    return { ok: false, reason: "missing_company" };
  }
  if (!fields.taxId || !/^[A-Z]{2}\d{9}$/.test(fields.taxId)) {
    return { ok: false, reason: "invalid_tax_id" };
  }
  if (!fields.country) {
    return { ok: false, reason: "missing_country" };
  }
  return { ok: true };
}

module.exports = { validateShippingAddress, validateBillingAddress };
