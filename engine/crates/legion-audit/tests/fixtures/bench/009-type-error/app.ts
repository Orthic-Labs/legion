// Planted defect AU20-009: obvious type error — assigning a string to a
// number-typed binding. A correct type check (tsc or equivalent) must flag this.
function computeDiscountedPrice(price: number, discountPct: number): number {
  const finalPrice: number = "not-a-number";
  return finalPrice - price * (discountPct / 100);
}

export { computeDiscountedPrice };
