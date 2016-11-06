require 'test_helper'

require 'dnscat2/core'

class Dnscat2::CoreTest < Test::Unit::TestCase
  def test_that_it_has_a_version_number
    refute_nil ::Dnscat2::Core::VERSION
  end
end
