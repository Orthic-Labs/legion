// Planted defect AU20-007: duplicated logic block (same body, copy-pasted).
function validateUsSignupForm(fields) {
  if (!fields.email || !fields.email.includes("@")) {
    return { ok: false, reason: "invalid_email" };
  }
  if (!fields.password || fields.password.length < 8) {
    return { ok: false, reason: "weak_password" };
  }
  if (!fields.country) {
    return { ok: false, reason: "missing_country" };
  }
  return { ok: true };
}

function validateEuSignupForm(fields) {
  if (!fields.email || !fields.email.includes("@")) {
    return { ok: false, reason: "invalid_email" };
  }
  if (!fields.password || fields.password.length < 8) {
    return { ok: false, reason: "weak_password" };
  }
  if (!fields.country) {
    return { ok: false, reason: "missing_country" };
  }
  return { ok: true };
}

module.exports = { validateUsSignupForm, validateEuSignupForm };
