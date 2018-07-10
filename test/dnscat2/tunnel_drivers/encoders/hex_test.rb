# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dnscat_exception'

require 'dnscat2/core/tunnel_drivers/encoders/hex'

module Dnscat2
  module Core
    module TunnelDrivers
      module Encoders
        class HexTest < ::Test::Unit::TestCase
          def test_characteristics()
            assert_equal("Hex encoder", Hex::NAME)
            assert_equal(2.0, Hex::RATIO)
          end

          def test_encode()
            assert_equal('4141', Hex.encode(data: 'AA'))
            assert_equal('', Hex.encode(data: ''))
          end

          def test_decode()
            assert_equal('AA', Hex.decode(data: '4141'))
            assert_equal('', Hex.decode(data: ''))
          end

          def test_decode_errors()
            assert_raises(DnscatException) do
              Hex.decode(data: 'gg')
            end

            assert_raises(DnscatException) do
              Hex.decode(data: '414')
            end
          end
        end
      end
    end
  end
end
