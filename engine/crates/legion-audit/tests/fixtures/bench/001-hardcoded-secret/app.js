// Planted defect AU20-001: hardcoded credential in source.
// The key below is a FAKE: it has the exact AWS access-key shape so a real
// scanner (gitleaks `aws-access-token`) recognises it, but it is not issued to
// any account. Do not "fix" it into an obviously-fake placeholder: gitleaks
// allowlists words like EXAMPLE, and the bench would stop detecting it.
function connect() {
  const awsAccessKeyId = "AKIAXQ7PLM3NB2ZRT5HY";
  const awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzXq9TnB4vLsA2d";
  return { awsAccessKeyId, awsSecretKey };
}

module.exports = { connect };
