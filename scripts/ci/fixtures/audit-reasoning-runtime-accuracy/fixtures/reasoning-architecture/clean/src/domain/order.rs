//! Domain modules depend on repository ports; they must not import or construct infrastructure adapters.
use crate::domain::repository::{Order, OrderRepository};
pub fn place_order<R: OrderRepository>(repository: &R, order: Order) { repository.save(order); }
