require 'minitest/autorun'
require_relative '../lib/answer'

class AnswerTest < Minitest::Test
  def test_answer
    warn "LEGION_PHP_RUBY_LIFECYCLE_TEST_STARTED"
    sleep 30
    assert_equal 42, answer
  end
end
