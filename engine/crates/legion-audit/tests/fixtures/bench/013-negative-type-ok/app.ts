// Negative control AU20-013: types are consistent throughout. A correct
// type check must NOT flag anything in this file.
function computeDiscountedPrice(price: number, discountPct: number): number {
  const finalPrice: number = price * (1 - discountPct / 100);
  return finalPrice;
}

export { computeDiscountedPrice };
