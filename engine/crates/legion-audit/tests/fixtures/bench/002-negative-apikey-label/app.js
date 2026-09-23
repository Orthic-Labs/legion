// Negative control AU20-002: a variable literally named "apiKey" that holds
// a UI label string, not a secret. A correct audit must NOT flag this line.
function renderSettingsField() {
  const apiKey = "Enter your API Key"; // UI placeholder text, not a credential
  return { label: apiKey };
}

module.exports = { renderSettingsField };
