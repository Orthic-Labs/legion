// Negative control AU20-010: a comment that references a credential ENV VAR
// NAME only (no value, no secret material). A correct audit must NOT flag
// this as a hardcoded secret — there is nothing here to leak.
// TODO: read STRIPE_SECRET_KEY from the vault at deploy time; never hardcode it.
function getStripeClient(env) {
  return { apiKey: env.STRIPE_SECRET_KEY };
}

module.exports = { getStripeClient };
