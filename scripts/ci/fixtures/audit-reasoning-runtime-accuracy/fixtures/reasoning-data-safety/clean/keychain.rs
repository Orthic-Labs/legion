pub fn save(token: &str) -> Result<(), keyring::Error> {
    keyring::Entry::new("fixture-service", "api-token")?.set_password(token)
}
