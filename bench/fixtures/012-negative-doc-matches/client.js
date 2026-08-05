// Negative control AU20-012: doc says 4 retries, code retries 4 times — no
// drift here. A correct audit must NOT flag this pair.
const MAX_RETRIES = 4;

function fetchWithRetry(fetchFn) {
  let attempt = 0;
  while (attempt < MAX_RETRIES) {
    try {
      return fetchFn();
    } catch {
      attempt += 1;
    }
  }
  throw new Error("exhausted retries");
}

module.exports = { fetchWithRetry, MAX_RETRIES };
