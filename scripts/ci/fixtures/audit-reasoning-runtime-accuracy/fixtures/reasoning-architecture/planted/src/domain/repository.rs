pub trait OrderRepository { fn save(&self, order: Order); }
pub struct Order;
