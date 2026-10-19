require 'minitest/autorun'
require_relative '../lib/answer'

class AnswerTest < Minitest::Test
  def test_answer
    assert_equal 42, answer
  end
end
