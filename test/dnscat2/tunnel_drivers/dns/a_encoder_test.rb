# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dnscat_exception'
require 'dnscat2/core/tunnel_drivers/encoders/base32'

require 'dnscat2/core/tunnel_drivers/dns/a_encoder'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class AEncoderTest < ::Test::Unit::TestCase
          def setup()
            @encoder = AEncoder.new(tag: 'abc', domain: 'def')
          end

          def test_encode_blank()
            #rr = @encoder.encode(data: '').pop()
            #assert_equal('', rr.data)
          end

          def test_encode_some_bytes()
            rrs = @encoder.encode(data: "ABCDEFGHIJ")
            assert_equal(4, rrs.length)
            assert_equal("1.10.65.66",  rrs[0].address.to_s)
            assert_equal("2.67.68.69",  rrs[1].address.to_s)
            assert_equal("3.70.71.72",  rrs[2].address.to_s)
            assert_equal("4.73.74.255", rrs[3].address.to_s)
          end

          def test_encode_one_byte()
            rrs = @encoder.encode(data: "A")
            assert_equal(1, rrs.length)
            assert_equal("1.1.65.255", rrs[0].address.to_s)
          end

          def test_encode_one_ip()
            rrs = @encoder.encode(data: "\x00\x00")
            assert_equal(1, rrs.length)
            assert_equal("1.2.0.0", rrs[0].address.to_s)
          end

          def test_encode_on_boundary()
            rrs = @encoder.encode(data: "ABCDEFGHIJK")
            assert_equal(4, rrs.length)
            assert_equal("1.11.65.66", rrs[0].address.to_s)
            assert_equal("2.67.68.69", rrs[1].address.to_s)
            assert_equal("3.70.71.72", rrs[2].address.to_s)
            assert_equal("4.73.74.75", rrs[3].address.to_s)
          end

          def test_encode_max_bytes()
            rrs = @encoder.encode(data: "A" * @encoder.max_length)
            assert_equal(63, rrs.length)
            assert_equal("1.188.65.65", rrs[0].address.to_s)

            1.upto(62) do |i|
              assert_equal("#{i+1}.65.65.65", rrs[i].address.to_s)
            end
          end

          def test_encode_max_bytes_plus_one()
            assert_raises(DnscatException) do
              @encoder.encode(data: "A" * (@encoder.max_length + 1))
            end
          end
        end
      end
    end
  end
end
