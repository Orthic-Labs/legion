export interface Order { id: string; total: number }
export const idOf = (order: Order): string => order.id;
