# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dnscat_exception'

require 'dnscat2/core/tunnel_drivers/dns/name_helper'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class NameHelperTest < ::Test::Unit::TestCase
          def test_max_length_different_tags()
            # Start with (255 - 4 periods) / 2 characters/byte => 125
            assert_equal(125, NameHelper.new(tag: nil,      domain: nil).max_length)

            # Prepending 'a.' means we have two less bytes, so (255 - 3 periods - 2 bytes) / 2 characters/byte => 125
            assert_equal(125, NameHelper.new(tag: 'a',      domain: nil).max_length)

            # Prepending 'aa.' means we have three less bytes, so (255 - 3 periods - 3 bytes) / 2 characters/byte => 124
            assert_equal(124, NameHelper.new(tag: 'aa',     domain: nil).max_length)

            # (255 - 3 - 4) / 2
            assert_equal(124, NameHelper.new(tag: 'aaa',    domain: nil).max_length)

            # (255 - 3 - 5) / 2
            assert_equal(123, NameHelper.new(tag: 'aaaa',   domain: nil).max_length)

            # (255 - 3 - 6) / 2
            assert_equal(123, NameHelper.new(tag: 'aaaaa',  domain: nil).max_length)

            # (255 - 3 - 7) / 2
            assert_equal(122, NameHelper.new(tag: 'aaaaaa', domain: nil).max_length)

            # Appending domains should be exactly the same as prepending a tag
            assert_equal(125, NameHelper.new(tag: nil, domain: nil).max_length)
            assert_equal(125, NameHelper.new(tag: nil, domain: 'a').max_length)
            assert_equal(124, NameHelper.new(tag: nil, domain: 'aa').max_length)
            assert_equal(124, NameHelper.new(tag: nil, domain: 'aaa').max_length)
            assert_equal(123, NameHelper.new(tag: nil, domain: 'aaaa').max_length)
            assert_equal(123, NameHelper.new(tag: nil, domain: 'aaaaa').max_length)
            assert_equal(122, NameHelper.new(tag: nil, domain: 'aaaaaa').max_length)
          end

          def test_max_length_different_segment_lengths()
            # The math to calculate these "correct" values is annoying.. it's floor((255 - ((255 + 1) / (n + 1))) / 2)
            assert_equal(63, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 1).max_length)
            assert_equal(85, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 2).max_length)
            assert_equal(95, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 3).max_length)
            assert_equal(102, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 4).max_length)
            assert_equal(106, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 5).max_length)
            assert_equal(109, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 6).max_length)
            assert_equal(111, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 7).max_length)
            assert_equal(113, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 8).max_length)
            assert_equal(115, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 9).max_length)
            assert_equal(116, NameHelper.new(tag: nil, domain: nil, max_subdomain_length: 10).max_length)
          end

          def test_encode()
            tests = [
              # Pretty normal test
              { tag: nil,   domain: nil,   data: 'AAAA', expected: '41414141',        max_subdomain_length: 63 },

              # Subdomain length of 1
              { tag: nil,   domain: nil,   data: 'AAAA', expected: '4.1.4.1.4.1.4.1', max_subdomain_length: 1 },

              # Add a tag
              { tag: 'abc', domain: nil,   data: 'AAAA', expected: 'abc.41414141',    max_subdomain_length: 63 },

              # Add a domain
              { tag: nil,   domain: 'abc', data: 'AAAA', expected: '41414141.abc',    max_subdomain_length: 63 },
            ]

            tests.each do |t|
              helper = NameHelper.new(tag: t[:tag], domain: t[:domain], max_subdomain_length: t[:max_subdomain_length])
              name = helper.encode_name(data: t[:data])
              assert_equal(t[:expected], name)
            end
          end

          def test_push_length_boundary()
            # This will mostly fail on its own if it creates a message that's too long
            1.upto(63) do |subdomain_length|
              0.upto(254) do |domain_length|
                n = NameHelper.new(tag: nil, domain: 'A' * domain_length, max_subdomain_length: subdomain_length)
                assert_not_nil(n.encode_name(data: ('a' * n.max_length)))
              end
            end
          end
        end
      end
    end
  end
end
