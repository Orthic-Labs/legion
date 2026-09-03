// Negative control. code.mobile ships only the Apple analyser, so Dart is
// not selected. See the corpus limitations field.
int total(List<int> prices) => prices.fold(0, (a, b) => a + b);
