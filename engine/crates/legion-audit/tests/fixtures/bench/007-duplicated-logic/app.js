// Planted defect AU20-007: duplicated logic block (same body, copy-pasted).
// The shared body is well over 20 lines, the registry's jscpd --min-lines threshold.
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
  if (!fields.name || fields.name.trim().length === 0) {
    return { ok: false, reason: "missing_name" };
  }
  if (!fields.phone || !/^[0-9+() -]{7,20}$/.test(fields.phone)) {
    return { ok: false, reason: "invalid_phone" };
  }
  if (fields.acceptedTerms !== true) {
    return { ok: false, reason: "terms_not_accepted" };
  }
  if (!fields.birthYear || fields.birthYear > 2010) {
    return { ok: false, reason: "too_young" };
  }
  if (fields.referral && fields.referral.length > 32) {
    return { ok: false, reason: "referral_too_long" };
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
  if (!fields.name || fields.name.trim().length === 0) {
    return { ok: false, reason: "missing_name" };
  }
  if (!fields.phone || !/^[0-9+() -]{7,20}$/.test(fields.phone)) {
    return { ok: false, reason: "invalid_phone" };
  }
  if (fields.acceptedTerms !== true) {
    return { ok: false, reason: "terms_not_accepted" };
  }
  if (!fields.birthYear || fields.birthYear > 2010) {
    return { ok: false, reason: "too_young" };
  }
  if (fields.referral && fields.referral.length > 32) {
    return { ok: false, reason: "referral_too_long" };
  }
  return { ok: true };
}

module.exports = { validateUsSignupForm, validateEuSignupForm };
