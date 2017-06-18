require 'test_helper'

require 'dnscat2/core/packets/enc_packet'

module Dnscat2
  module Core
    module Packets
      class EncPacketInitTest < ::Test::Unit::TestCase
        def test_create()
          packet = EncPacketInit.new(public_key_x: 1, public_key_y: 2)
          assert_equal(1, packet.public_key_x)
          assert_equal(2, packet.public_key_y)
        end

        def test_parse()
          packet = EncPacketInit.parse(
            ("\x00" * 31 + "\x01") +
            ("\x00" * 31 + "\x02")
          )
          assert_equal(1, packet.public_key_x)
          assert_equal(2, packet.public_key_y)
        end

        def test_parse_too_short()
          assert_raises(DnscatException) do
            EncPacketInit.parse("\x00" * 63)
          end
        end

        def test_parse_too_long()
          assert_raises(DnscatException) do
            EncPacketInit.parse("\x00" * 65)
          end
        end

        def test_to_bytes()
          packet = EncPacketInit.new(public_key_x: 1, public_key_y: 2)
          assert_equal(("\x00" * 31 + "\x01") + ("\x00" * 31 + "\x02"), packet.to_bytes())
        end

        def test_to_s()
          packet = EncPacketInit.new(public_key_x: 0x10, public_key_y: 0x20)
          assert_equal("[[INIT]] :: pubkey = " +
                       "0x0000000000000000000000000000000000000000000000000000000000000010," +
                       "0x0000000000000000000000000000000000000000000000000000000000000020",
                       packet.to_s)
        end
      end
    end
  end
end
