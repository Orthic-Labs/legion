# Negative control. code.php-ruby ships only the PHP analyser, so a Ruby
# source file is not selected. See the corpus limitations field.
class Order
  def total(items)
    items.sum
  end
end
