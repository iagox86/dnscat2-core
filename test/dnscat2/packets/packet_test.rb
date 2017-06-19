# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/packets/packet'

module Dnscat2
  module Core
    module Packets
      class PacketTest < ::Test::Unit::TestCase
        def test_syn()
          packet = Packet.create_syn(
            session_id: 0x1122,
            isn: 0x3344,
            name: 'test'
          )
          assert_equal(0x1122, packet.session_id)
          assert_equal(0x3344, packet.body.isn)
          assert_equal('test', packet.body.name)

          bytes = packet.to_bytes()

          # Set the packet_id to a known value, since it's random
          bytes[0,2] = "\xFF\xFF"

          assert_equal("\xFF\xFF\x00\x11\x22" + # Header
                       "\x33\x44\x00\x01test\x00", # Body
                       bytes)

          packet = Packet.parse(bytes)
          assert_equal(0x1122, packet.session_id)
          assert_equal(0x3344, packet.body.isn)
          assert_equal('test', packet.body.name)

          expected = "[0xffff] session = 0x1122 :: [[SYN]] :: isn = 0x3344, name = test"
          assert_equal(expected, packet.to_s)
        end

        def test_syn_no_name()
          packet = Packet.create_syn(
            session_id: 0x1122,
            isn: 0x3344,
          )
          assert_equal(0x1122, packet.session_id)
          assert_equal(0x3344, packet.body.isn)
          assert_equal(nil, packet.body.name)

          bytes = packet.to_bytes()

          # Set the packet_id to a known value, since it's random
          bytes[0,2] = "\xFF\xFF"

          assert_equal("\xFF\xFF\x00\x11\x22" + # Header
                       "\x33\x44\x00\x00", # Body
                       bytes)

          packet = Packet.parse(bytes)
          assert_equal(0x1122, packet.session_id)
          assert_equal(0x3344, packet.body.isn)
          assert_equal(nil, packet.body.name)

          expected = "[0xffff] session = 0x1122 :: [[SYN]] :: isn = 0x3344, name = (n/a)"
          assert_equal(expected, packet.to_s)
        end

        def test_fin()
          packet = Packet.create_fin(
            options: 0,
            session_id: 0x1122,
            reason: 'test'
          )
          assert_equal(0x1122, packet.session_id)
          assert_equal('test', packet.body.reason)

          bytes = packet.to_bytes()

          # Set the packet_id to a known value, since it's random
          bytes[0,2] = "\xFF\xFF"

          assert_equal("\xFF\xFF\x02\x11\x22" + # Header
                       "test\x00", # Body
                       bytes)

          packet = Packet.parse(bytes, options: 0)
          assert_equal(0x1122, packet.session_id)
          assert_equal('test', packet.body.reason)

          expected = "[0xffff] session = 0x1122 :: [[FIN]] :: reason = test"
          assert_equal(expected, packet.to_s)
        end

        def test_msg()
          packet = Packet.create_msg(
            options: 0,
            session_id: 0x1122,
            seq: 0x3344,
            ack: 0x5566,
            data: 'test'
          )
          assert_equal(0x1122, packet.session_id)
          assert_equal(0x3344, packet.body.seq)
          assert_equal(0x5566, packet.body.ack)
          assert_equal('test', packet.body.data)
          bytes = packet.to_bytes()

          # Set the packet_id to a known value, since it's random
          bytes[0,2] = "\xFF\xFF"

          assert_equal("\xFF\xFF\x01\x11\x22" + # Header
                       "\x33\x44\x55\x66test", # Body
                       bytes)

          packet = Packet.parse(bytes, options: 0)
          assert_equal(0x1122, packet.session_id)
          assert_equal(0x3344, packet.body.seq)
          assert_equal(0x5566, packet.body.ack)
          assert_equal('test', packet.body.data)

          expected = "[0xffff] session = 0x1122 :: [[MSG]] :: seq = 0x3344, ack = 0x5566, data = (0x4 bytes)"
          assert_equal(expected, packet.to_s)
        end

        def test_enc_init()
          packet = Packet.create_enc_init(
            session_id: 0x1122,
            public_key_x: 0x10,
            public_key_y: 0x20,
          )
          assert_equal(0x1122, packet.session_id)
          assert_equal(0x10, packet.body.body.public_key_x)
          assert_equal(0x20, packet.body.body.public_key_y)
          bytes = packet.to_bytes()

          # Set the packet_id to a known value, since it's random
          bytes[0,2] = "\xFF\xFF"

          assert_equal("\xFF\xFF\x03\x11\x22" + # Header
                       "\x00\x00\x00\x00" + # Body
                       ("\x00" * 31) + "\x10" +
                       ("\x00" * 31) + "\x20",
                       bytes)

          packet = Packet.parse(bytes)

          assert_equal(0x1122, packet.session_id)
          assert_equal(0x10, packet.body.body.public_key_x)
          assert_equal(0x20, packet.body.body.public_key_y)

          expected = "[0xffff] session = 0x1122 :: [[ENC]] :: flags = 0x0000 " +
                     "[[INIT]] :: pubkey = " +
                       "0x0000000000000000000000000000000000000000000000000000000000000010," +
                       "0x0000000000000000000000000000000000000000000000000000000000000020"
          assert_equal(expected, packet.to_s)
        end

        def test_enc_auth()
          packet = Packet.create_enc_auth(
            session_id: 0x1122,
            authenticator: 0x30,
          )
          assert_equal(0x1122, packet.session_id)
          assert_equal(0x30, packet.body.body.authenticator)
          bytes = packet.to_bytes()

          # Set the packet_id to a known value, since it's random
          bytes[0,2] = "\xFF\xFF"

          assert_equal("\xFF\xFF\x03\x11\x22" + # Header
                       "\x00\x01\x00\x00" + # Body
                       ("\x00" * 31) + "\x30",
                       bytes)

          packet = Packet.parse(bytes)

          assert_equal(0x1122, packet.session_id)
          assert_equal(0x30, packet.body.body.authenticator)

          expected = "[0xffff] session = 0x1122 :: [[ENC]] :: flags = 0x0000 " +
                     "[[AUTH]] :: authenticator = " +
                       "0x0000000000000000000000000000000000000000000000000000000000000030"
          assert_equal(expected, packet.to_s)
        end

        def test_ping()
          packet = Packet.create_ping(
            options: 0,
            ping_id: 0x1122,
            body: 'test'
          )
          assert_equal(0x1122, packet.session_id)
          assert_equal('test', packet.body.body)
          bytes = packet.to_bytes()

          # Set the packet_id to a known value, since it's random
          bytes[0,2] = "\xFF\xFF"

          assert_equal("\xFF\xFF\xFF\x11\x22" + # Header
                       "test\x00", # Body
                       bytes)

          packet = Packet.parse(bytes, options: 0)
          assert_equal(0x1122, packet.session_id)
          assert_equal('test', packet.body.body)

          expected = "[0xffff] session = 0x1122 :: [[PING]] :: body = test"
          assert_equal(expected, packet.to_s)
        end

        def test_short()
          assert_raises(DnscatException) do
            Packet.parse("\xFF\xFF\x00\x11\x22\x33\x44\x00")
          end
          assert_raises(DnscatException) do
            Packet.parse("\xFF\xFF\x00\x11\x22\x33\x44")
          end
          assert_raises(DnscatException) do
            Packet.parse("\xFF\xFF\x00\x11\x22\x33")
          end
          assert_raises(DnscatException) do
            Packet.parse("\xFF\xFF\x00\x11\x22")
          end
          assert_raises(DnscatException) do
            Packet.parse("\xFF\xFF\x00\x11")
          end
          assert_raises(DnscatException) do
            Packet.parse("\xFF\xFF\x00")
          end
          assert_raises(DnscatException) do
            Packet.parse("\xFF\xFF")
          end
          assert_raises(DnscatException) do
            Packet.parse("\xFF")
          end
          assert_raises(DnscatException) do
            Packet.parse("")
          end
        end

        def test_peek()
          data = "\xFF\xFF\x00\x11\x22\x33\x44\x00\x01test\x00"
          assert_equal(0x1122, Packet.peek_session_id(data))
          assert_equal(MESSAGE_TYPE_SYN, Packet.peek_type(data))
        end

        def test_not_nulls()
          data = "\xFF\xFF\x01\x11\x22\x33\x44\x00\x01test\x00"
          assert_raises(DnscatException) do
            Packet.parse(data)
          end

          data = "\xFF\xFF\x02\x11\x22\x33\x44\x00\x01test\x00"
          assert_raises(DnscatException) do
            Packet.parse(data)
          end
        end

        def test_parse_bad_packet()
          data = "\xFF\xFF\x80\x11\x22\x33\x44\x00\x01test\x00"
          assert_raises(DnscatException) do
            Packet.parse(data)
          end
        end
      end
    end
  end
end
