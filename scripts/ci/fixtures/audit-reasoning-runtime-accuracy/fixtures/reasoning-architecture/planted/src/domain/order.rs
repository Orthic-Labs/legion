//! Domain modules depend on repository ports; they must not import or construct infrastructure adapters.
use crate::infra::postgres::repository::PgRepository;
use crate::domain::repository::Order;
pub fn place_order(order: Order) { let db = PgRepository::connect(); db.save(order); }
