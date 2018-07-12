# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dnscat_exception'

require 'dnscat2/core/tunnel_drivers/dns/txt_encoder'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class TXTEncoderTest < ::Test::Unit::TestCase
          def setup()
            @encoder = TXTEncoder.new(tag: 'abc', domain: 'def')
          end

          def test_max_length()
            # This is trivial, since the TXTEncoder always has room for 254
            # bytes (halved because of encoding)
            assert_equal(126, @encoder.max_length)
          end

          def test_encode_blank()
            rr = @encoder.encode(data: '')

            assert_equal('', rr.data)
          end

          def test_encode_max_bytes()
            rr = @encoder.encode(data: 'A' * @encoder.max_length())
            assert_equal('41' * @encoder.max_length, rr.data)
          end

          def test_encode_128_bytes()
            e = assert_raises(DnscatException) do
              @encoder.encode(data: 'A' * (@encoder.max_length() + 1))
            end

            assert_not_nil(e.message =~ /too much data/)
          end
        end
      end
    end
  end
end
