# Encoding: ASCII-8BIT
require 'test_helper'
require 'dnscat2/core/packets/ping_packet'

module Dnscat2
  module Core
    module Packets
      class PingPacketTest < ::Test::Unit::TestCase
        def test_create()
          packet = PingPacket.new(
            options: 0,
            body: 'hi',
          )
          assert_equal(0, packet.options)
          assert_equal('hi', packet.body)
        end

        def test_create_no_body()
          packet = PingPacket.new(
            options: 0,
            body: '',
          )
          assert_equal(0, packet.options)
          assert_equal('', packet.body)
        end

        def test_parse()
          packet = PingPacket.parse(0, "hi\x00")

          assert_equal(0, packet.options)
          assert_equal('hi', packet.body)
        end

        def test_parse_no_body()
          packet = PingPacket.parse(0, "\x00")

          assert_equal(0, packet.options)
          assert_equal('', packet.body)
        end

        def test_to_bytes()
          packet = PingPacket.new(
            options: 0,
            body: 'hi',
          )
          assert_equal("hi\x00", packet.to_bytes())
        end

        def test_to_bytes_no_body()
          packet = PingPacket.new(
            options: 0,
            body: ''
          )
          assert_equal("\x00", packet.to_bytes())
        end

        def test_to_s()
          packet = PingPacket.new(
            options: 0,
            body: 'hi'
          )
          assert_equal("[[PING]] :: body = hi", packet.to_s())
        end

        def test_to_s_no_body()
          packet = PingPacket.new(
            options: 0,
            body: ''
          )
          assert_equal("[[PING]] :: body = ", packet.to_s())
        end

        def test_no_null_terminator()
          assert_raises(DnscatException) do
            PingPacket.parse(0, 'hi')
          end
        end

        def test_no_body()
          assert_raises(DnscatException) do
            PingPacket.parse(0, '')
          end
        end
      end
    end
  end
end
