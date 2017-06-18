require 'test_helper'

require 'dnscat2/core/packets/fin_packet'

module Dnscat2
  module Core
    module Packets
      class FinPacketTest < ::Test::Unit::TestCase
        def test_create()
          packet = FinPacket.new(
            options: 0,
            reason: 'hi',
          )
          assert_equal(0, packet.options)
          assert_equal('hi', packet.reason)
        end

        def test_create_no_reason()
          packet = FinPacket.new(
            options: 0,
            reason: '',
          )
          assert_equal(0, packet.options)
          assert_equal('', packet.reason)
        end

        def test_parse()
          packet = FinPacket.parse(0, "hi\x00")

          assert_equal(0, packet.options)
          assert_equal('hi', packet.reason)
        end

        def test_parse_no_reason()
          packet = FinPacket.parse(0, "\x00")

          assert_equal(0, packet.options)
          assert_equal('', packet.reason)
        end

        def test_to_bytes()
          packet = FinPacket.new(
            options: 0,
            reason: 'hi',
          )
          assert_equal("hi\x00", packet.to_bytes())
        end

        def test_to_bytes_no_reason()
          packet = FinPacket.new(
            options: 0,
            reason: ''
          )
          assert_equal("\x00", packet.to_bytes())
        end

        def test_to_s()
          packet = FinPacket.new(
            options: 0,
            reason: 'hi'
          )
          assert_equal("[[FIN]] :: reason = hi", packet.to_s())
        end

        def test_to_s_no_reason()
          packet = FinPacket.new(
            options: 0,
            reason: ''
          )
          assert_equal("[[FIN]] :: reason = ", packet.to_s())
        end

        def test_no_null_terminator()
          assert_raises(DnscatException) do
            FinPacket.parse(0, 'hi')
          end
        end

        def test_no_reason()
          assert_raises(DnscatException) do
            FinPacket.parse(0, '')
          end
        end
      end
    end
  end
end
