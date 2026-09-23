// Planted defect AU20-001: hardcoded credential in source.
// The key below is a FAKE, OBVIOUSLY-NOT-REAL example key — never a live credential.
function connect() {
  const awsAccessKeyId = "AKIA_EXAMPLE_NOT_REAL_00000001";
  const awsSecretKey = "EXAMPLE/NOTREAL/SECRETKEY0000000000000001";
  return { awsAccessKeyId, awsSecretKey };
}

module.exports = { connect };
