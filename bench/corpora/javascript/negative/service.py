// Negative control: a Python module. No JavaScript-family extension, so the
// javascript provider must never place it in a denominator.
def total(items):
    return sum(item["price"] for item in items)
