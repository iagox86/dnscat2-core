require 'test_helper'

require 'dnscat2/core/packets/msg_packet'

module Dnscat2
  module Core
    module Packets
      class MsgPacketTest < ::Test::Unit::TestCase
        def test_create()
          packet = MsgPacket.new(
            options: 0,
            seq: 0x1122,
            ack: 0x3344,
            data: 'data'
          )
          assert_equal(0, packet.options)
          assert_equal(0x1122, packet.seq)
          assert_equal(0x3344, packet.ack)
          assert_equal('data', packet.data)
        end

        def test_create_no_data()
          packet = MsgPacket.new(
            options: 0,
            seq: 0x1122,
            ack: 0x3344,
            data: ''
          )
          assert_equal(0, packet.options)
          assert_equal(0x1122, packet.seq)
          assert_equal(0x3344, packet.ack)
          assert_equal('', packet.data)
        end

        def test_parse()
          packet = MsgPacket.parse(0, "\x11\x22\x33\x44data")

          assert_equal(0, packet.options)
          assert_equal(0x1122, packet.seq)
          assert_equal(0x3344, packet.ack)
          assert_equal('data', packet.data)
        end

        def test_parse_no_data()
          packet = MsgPacket.parse(0, "\x11\x22\x33\x44")

          assert_equal(0, packet.options)
          assert_equal(0x1122, packet.seq)
          assert_equal(0x3344, packet.ack)
          assert_equal('', packet.data)
        end

        def test_to_bytes()
          packet = MsgPacket.new(
            options: 0,
            seq: 0x1122,
            ack: 0x3344,
            data: 'data'
          )
          assert_equal("\x11\x22\x33\x44data", packet.to_bytes())
        end

        def test_to_bytes_no_data()
          packet = MsgPacket.new(
            options: 0,
            seq: 0x1122,
            ack: 0x3344,
            data: ''
          )
          assert_equal("\x11\x22\x33\x44", packet.to_bytes())
        end

        def test_to_s()
          packet = MsgPacket.new(
            options: 0,
            seq: 0x1122,
            ack: 0x3344,
            data: 'data'
          )
          assert_equal("[[MSG]] :: seq = 0x1122, ack = 0x3344, data = (0x4 bytes)", packet.to_s())
        end

        def test_to_s_no_data()
          packet = MsgPacket.new(
            options: 0,
            seq: 0x1122,
            ack: 0x3344,
            data: ''
          )
          assert_equal("[[MSG]] :: seq = 0x1122, ack = 0x3344, data = (0x0 bytes)", packet.to_s())
        end

        def test_too_short()
          assert_raises(DnscatException) do
            MsgPacket.parse(0, "\x11\x22\x33")
          end
          assert_raises(DnscatException) do
            MsgPacket.parse(0, "\x11\x22")
          end
          assert_raises(DnscatException) do
            MsgPacket.parse(0, "\x11")
          end
          assert_raises(DnscatException) do
            MsgPacket.parse(0, "")
          end
        end
      end
    end
  end
end
