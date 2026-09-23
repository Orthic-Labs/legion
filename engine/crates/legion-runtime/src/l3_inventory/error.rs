/// Port of the plain `Error(message)` throws scattered across
/// `src/lib/inventory/**`. Every JS throw site becomes one `Err` here.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct InventoryError(pub String);

impl InventoryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}
