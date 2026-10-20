pub struct PgRepository;
impl PgRepository { pub fn connect() -> Self { Self } }
impl crate::domain::repository::OrderRepository for PgRepository { fn save(&self, _order: crate::domain::repository::Order) {} }
