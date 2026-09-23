// Planted defect AU20-011: doc says 3 retries, code actually retries 5 times.
// This is intentional drift the bench should catch, not a bug fix target.
const MAX_RETRIES = 5;

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
