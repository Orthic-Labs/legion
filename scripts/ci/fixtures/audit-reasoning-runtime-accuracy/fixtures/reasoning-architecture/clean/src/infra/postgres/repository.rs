pub struct PgRepository;
impl crate::domain::repository::OrderRepository for PgRepository { fn save(&self, _order: crate::domain::repository::Order) {} }
