# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dnscat_exception'

require 'dnscat2/core/tunnel_drivers/dns/txt_handler'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class TXTHandlerTest < ::Test::Unit::TestCase
          def setup()
            @handler = TXTHandler.new(tag: 'abc', domain: 'def')
          end

          def test_max_length()
            # This is trivial, since the TXTHandler always has room for 254
            # bytes (halved because of encoding)
            assert_equal(127, @handler.max_length)
          end

          def test_encode_blank()
            rr = @handler.encode(data: '')

            assert_equal('', rr.data)
          end

          def test_encode_127_bytes()
            rr = @handler.encode(data: 'A' * 127)
            assert_equal('41' * 127, rr.data)
          end

          def test_encode_128_bytes()
            e = assert_raises(DnscatException) do
              @handler.encode(data: 'A' * 128)
            end

            assert_not_nil(e.message =~ /too much data/)
          end
        end
      end
    end
  end
end

#      class SynPacketTest < ::Test::Unit::TestCase
#        def test_create_no_name()
#          packet = SynPacket.new(isn: 0x1122, name: nil)
#          assert_equal("\x11\x22\x00\x00", packet.to_bytes())
#        end
