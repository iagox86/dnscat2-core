# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dnscat_exception'

require 'dnscat2/core/tunnel_drivers/dns/name_helper'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class NameHelperTest < ::Test::Unit::TestCase
          def setup()
          end

          def test_max_length()
            # Start with (255 - 4 periods) / 2 characters/byte => 125
            assert_equal(125, NameHelper.new(tag: nil, domain: nil, max_subdomain_jitter: 0).max_length)

            # Prepending 'a.' means we have two less bytes, so (255 - 3 periods - 2 bytes) / 2 characters/byte => 125
            assert_equal(125, NameHelper.new(tag: 'a', domain: nil, max_subdomain_jitter: 0).max_length)

            # Prepending 'aa.' means we have three less bytes, so (255 - 3 periods - 3 bytes) / 2 characters/byte => 124
            assert_equal(124, NameHelper.new(tag: 'aa', domain: nil, max_subdomain_jitter: 0).max_length)

            # (255 - 3 - 4) / 2
            assert_equal(124, NameHelper.new(tag: 'aaa', domain: nil, max_subdomain_jitter: 0).max_length)

            # (255 - 3 - 5) / 2
            assert_equal(123, NameHelper.new(tag: 'aaaa', domain: nil, max_subdomain_jitter: 0).max_length)

            # (255 - 3 - 6) / 2
            assert_equal(123, NameHelper.new(tag: 'aaaaa', domain: nil, max_subdomain_jitter: 0).max_length)

            # (255 - 3 - 7) / 2
            assert_equal(122, NameHelper.new(tag: 'aaaaaa', domain: nil, max_subdomain_jitter: 0).max_length)
#
#            # Appending domains should be exactly the same as prepending a tag
#            assert_equal(125, NameHelper.new(tag: nil, domain: 'a', max_subdomain_jitter: 0).max_length)
#            assert_equal(124, NameHelper.new(tag: nil, domain: 'aa', max_subdomain_jitter: 0).max_length)
#            assert_equal(124, NameHelper.new(tag: nil, domain: 'aaa', max_subdomain_jitter: 0).max_length)
#            assert_equal(123, NameHelper.new(tag: nil, domain: 'aaaa', max_subdomain_jitter: 0).max_length)
#            assert_equal(123, NameHelper.new(tag: nil, domain: 'aaaaa', max_subdomain_jitter: 0).max_length)
#            assert_equal(122, NameHelper.new(tag: nil, domain: 'aaaaaa', max_subdomain_jitter: 0).max_length)
          end

#          def test_max_length_different_segment_lengths()
#            assert_equal(63, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 1, max_subdomain_jitter: 0).max_length)
#            assert_equal(85, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 2, max_subdomain_jitter: 0).max_length)
#            assert_equal(96, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 3, max_subdomain_jitter: 0).max_length)
#
#            # Test with jitter
#            assert_equal(85, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 3, max_subdomain_jitter: 1).max_length)
#            assert_equal(64, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 3, max_subdomain_jitter: 2).max_length)
#          end
#
#          def test_encode()
#            tests = [
#              { tag: nil, domain: nil, data: 'AAAA', expected: '41414141', max_subdomain_length: 63, max_subdomain_jitter: 0 }
#            ]
#
#            tests.each do |t|
#              helper = NameHelper.new(tag: t[:tag], domain: t[:domain], max_subdomain_length: t[:max_subdomain_length], max_subdomain_jitter: t[:max_subdomain_jitter])
#              name = helper.encode_name(data: t[:data])
#              assert_equal(t[:expected], name.gsub(/\./, '')) # Remove periods so jitter doesn't break tests
#            end
#          end
#
#          def test_push_length_boundary()
#            1.upto(63) do |i|
#              n = NameHelper.new(tag: nil, domain: nil, max_subdomain_length: i, max_subdomain_jitter: 0)
#              n.encode_name(data: ('a' * n.max_length))
#            end
#
#            # Then with jitter
#            2.upto(63) do |i|
#              n = NameHelper.new(tag: nil, domain: nil, max_subdomain_length: i, max_subdomain_jitter: rand(1..i-1))
#              n.encode_name(data: ('a' * n.max_length))
#            end
#          end
        end
      end
    end
  end
end
