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

      class EncPacketAuthTest < ::Test::Unit::TestCase
        def test_create()
          packet = EncPacketAuth.new(authenticator: 1)
          assert_equal(1, packet.authenticator)
        end

        def test_parse()
          packet = EncPacketAuth.parse(("\x00" * 31) + "\x01")
          assert_equal(1, packet.authenticator)
        end

        def test_parse_too_short()
          assert_raises(DnscatException) do
            EncPacketAuth.parse("\x00" * 63)
          end
        end

        def test_parse_too_long()
          assert_raises(DnscatException) do
            EncPacketAuth.parse("\x00" * 65)
          end
        end

        def test_to_bytes()
          packet = EncPacketAuth.new(authenticator: 1)
          assert_equal(("\x00" * 31 + "\x01"), packet.to_bytes())
        end

        def test_to_s()
          packet = EncPacketAuth.new(authenticator: 0x10)
          assert_equal("[[AUTH]] :: authenticator = " +
                       "0x0000000000000000000000000000000000000000000000000000000000000010",
                       packet.to_s)
        end
      end

      class EncPacketTest < ::Test::Unit::TestCase
        def test_create_init()
          subpacket = EncPacketInit.new(public_key_x: 1, public_key_y: 2)
          packet = EncPacket.new(flags: 0, body: subpacket)

          assert_equal(0, packet.flags)
          assert_equal(SUBTYPE_INIT, packet.subtype)
          assert_equal(subpacket, packet.body)
        end

        def test_create_auth()
          subpacket = EncPacketAuth.new(authenticator: 3)
          packet = EncPacket.new(flags: 0, body: subpacket)

          assert_equal(0, packet.flags)
          assert_equal(SUBTYPE_AUTH, packet.subtype)
          assert_equal(subpacket, packet.body)
        end

        def test_create_bad()
          assert_raises(DnscatException) do
            EncPacket.new(flags: 0, body: 'hi')
          end
        end

        def test_parse_init()
          packet = EncPacket.parse("\x00\x00\x00\x00" +
            ("\x00" * 31 + "\x01") +
            ("\x00" * 31 + "\x02")
          )
          assert_equal(0, packet.flags)
          assert_equal(SUBTYPE_INIT, packet.subtype)
          assert_equal(1, packet.body.public_key_x)
          assert_equal(2, packet.body.public_key_y)
        end

        def test_parse_auth()
          packet = EncPacket.parse("\x00\x01\x00\x00" + ("\x00" * 31 + "\x03"))
          assert_equal(0, packet.flags)
          assert_equal(SUBTYPE_AUTH, packet.subtype)
          assert_equal(3, packet.body.authenticator)
        end

        def test_parse()
          assert_raises(DnscatException) do
            EncPacket.parse("\x00\x02\x00\x00\x00")
          end
        end

        def test_parse_too_short()
          assert_raises(DnscatException) do
            EncPacket.parse("\x00\x00\x00\x00")
          end
          assert_raises(DnscatException) do
            EncPacket.parse("\x00\x00\x00")
          end
          assert_raises(DnscatException) do
            EncPacket.parse("\x00\x00")
          end
          assert_raises(DnscatException) do
            EncPacket.parse("\x00")
          end
          assert_raises(DnscatException) do
            EncPacket.parse("")
          end
        end

        def test_to_bytes_init()
          subpacket = EncPacketInit.new(public_key_x: 1, public_key_y: 2)
          packet = EncPacket.new(flags: 0, body: subpacket)

          expected = "\x00\x00\x00\x00" + ("\x00" * 31 + "\x01") + ("\x00" * 31 + "\x02")
          assert_equal(expected, packet.to_bytes())
        end

        def test_to_bytes_auth()
          subpacket = EncPacketAuth.new(authenticator: 3)
          packet = EncPacket.new(flags: 0, body: subpacket)

          expected = "\x00\x01\x00\x00" + ("\x00" * 31 + "\x03")
          assert_equal(expected, packet.to_bytes())
        end

        def test_to_s_init()
          subpacket = EncPacketInit.new(public_key_x: 0x10, public_key_y: 0x20)
          packet = EncPacket.new(flags: 0, body: subpacket)

          expected = "[[ENC]] :: flags = 0x0000 " +
            "[[INIT]] :: pubkey = " +
            "0x0000000000000000000000000000000000000000000000000000000000000010," +
            "0x0000000000000000000000000000000000000000000000000000000000000020"

          assert_equal(expected, packet.to_s)
        end

        def test_to_s_auth()
          subpacket = EncPacketAuth.new(authenticator: 0x30)
          packet = EncPacket.new(flags: 0, body: subpacket)

          expected = "[[ENC]] :: flags = 0x0000 " +
            "[[AUTH]] :: authenticator = " +
            "0x0000000000000000000000000000000000000000000000000000000000000030"

          assert_equal(expected, packet.to_s)
        end
      end
    end
  end
end
