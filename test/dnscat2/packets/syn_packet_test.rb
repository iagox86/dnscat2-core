require 'test_helper'

require 'dnscat2/core/packets/syn_packet'

module Dnscat2
  module Core
    module Packets
      class SynPacketTest < ::Test::Unit::TestCase
        def test_create_no_name()
          packet = SynPacket.new(isn: 0x1122, name: nil)
          assert_equal("\x11\x22\x00\x00", packet.to_bytes())
        end

        def test_create_with_name()
          packet = SynPacket.new(isn: 0x1122, name: "testname")
          assert_equal("\x11\x22\x00\x01testname\x00", packet.to_bytes())
        end

        def test_parse_no_name()
          packet = SynPacket.parse("\x11\x22\x00\x00")
          assert_equal(0x1122, packet.isn)
          assert_nil(packet.name)
        end

        def test_parse_with_name()
          packet = SynPacket.parse("\x11\x22\x00\x01testname\x00")
          assert_equal(0x1122, packet.isn)
          assert_equal("testname", packet.name)
        end

        def test_parse_name_not_null_terminated()
          assert_raises(DnscatException) do
            SynPacket.parse("\x11\x22\x00\x01testname")
          end
        end

        def test_parse_too_short()
          assert_raises(DnscatException) do
            SynPacket.parse("\x11\x22\x00")
          end
          assert_raises(DnscatException) do
            SynPacket.parse("\x11\x22")
          end
          assert_raises(DnscatException) do
            SynPacket.parse("\x11")
          end
          assert_raises(DnscatException) do
            SynPacket.parse("")
          end
        end

        def test_parse_too_long()
          1.upto(16) do |i|
            assert_raises(DnscatException) do
              SynPacket.parse("\x11\x22\x00\x00" + ("\x00" * i))
            end
          end
        end

        def test_parse_too_long_with_name()
          1.upto(16) do |i|
            assert_raises(DnscatException) do
              SynPacket.parse("\x11\x22\x00\x01testname\x00" + ("\x00" * i))
            end
          end
        end

        def test_to_s_with_name()
          packet = SynPacket.new(isn: 0x1122, name: "testname")
          assert_equal(
            "[[SYN]] :: isn = 0x1122, name = testname",
            packet.to_s()
          )
        end

        def test_to_s_without_name()
          packet = SynPacket.new(isn: 0x1122)
          assert_equal(
            "[[SYN]] :: isn = 0x1122, name = (n/a)",
            packet.to_s()
          )
        end
      end
    end
  end
end
