# Encoding: ASCII-8BIT
##
# packet.rb
# Created March, 2013
# By Ron Bowes
#
# See: LICENSE.md
#
# Builds and parses dnscat2 packets.
##

require 'hexhelper'

require 'dnscat2/core/libs/dnscat_exception'
require 'dnscat2/core/packets/enc_packet'
require 'dnscat2/core/packets/fin_packet'
require 'dnscat2/core/packets/msg_packet'
require 'dnscat2/core/packets/packet_constants'
require 'dnscat2/core/packets/packet_helper'
require 'dnscat2/core/packets/syn_packet'

module Dnscat2
  module Core
    module Packets
      class Packet
        extend PacketHelper
        attr_reader :packet_id, :type, :session_id, :body

        private
        def initialize(packet_id:nil, session_id:, body:)
          if body.is_a?(EncPacket)
            @type = MESSAGE_TYPE_ENC
          elsif body.is_a?(FinPacket)
            @type = MESSAGE_TYPE_FIN
          elsif body.is_a?(MsgPacket)
            @type = MESSAGE_TYPE_MSG
          elsif body.is_a?(SynPacket)
            @type = MESSAGE_TYPE_SYN
          elsif body.is_a?(PingPacket)
            @type = MESSAGE_TYPE_PING
          else
            raise(DnscatException, "Unknown message type: %s" % body.class)
          end

          @packet_id = packet_id || rand(0xFFFF)
          @session_id = session_id
          @body = body
        end

        private
        def self.parse_header(data)
          verify_length!(data, 5)

          # (uint16_t) packet_id
          # (uint8_t) message_type
          # (uint16_t) session_id
          return data.unpack("nCna*")
        end

        public
        def self.peek_session_id(data)
          _, _, session_id, _ = Packet.parse_header(data)

          return session_id
        end

        public
        def self.peek_type(data)
          _, type, _, _ = Packet.parse_header(data)
          return type
        end

        public
        def self.parse(data, options:nil)
          packet_id, type, session_id, data = self.parse_header(data)

          case type
          when MESSAGE_TYPE_SYN
            body = SynPacket.parse(data)
          when MESSAGE_TYPE_MSG
            verify_not_null!(options, "`options` is required when parsing a MSG packet!")
            body = MsgPacket.parse(options, data)
          when MESSAGE_TYPE_FIN
            verify_not_null!(options, "`options` is required when parsing a FIN packet!")
            body = FinPacket.parse(options, data)
          when MESSAGE_TYPE_PING
            body = PingPacket.parse(nil, data)
          when MESSAGE_TYPE_ENC
            body = EncPacket.parse(data)
          else
            raise(DnscatException, "Unknown message type: 0x%x" % type)
          end

          return Packet.new(packet_id: packet_id, session_id: session_id, body: body)
        end

        def self.create_syn(session_id:, isn:, name:nil)
          return Packet.new(
            session_id: session_id,
            body: SynPacket.new(
              isn: isn,
              name: name,
            )
          )
        end

        def self.create_msg(options:, session_id:, seq:, ack:, data:)
          return Packet.new(
            session_id: session_id,
            body: MsgPacket.new(
              options: options,
              seq: seq,
              ack: ack,
              data: data,
            )
          )
        end

        def self.create_fin(options:, session_id:, reason:)
          return Packet.new(
            session_id: session_id,
            body: FinPacket.new(
              options: options,
              reason: reason,
            )
          )
        end

        def self.create_ping(options:, ping_id:, body:)
          return Packet.new(
            session_id: ping_id,
            body: PingPacket.new(
              options: options,
              body: body,
            )
          )
        end

        def self.create_enc_init(session_id:, public_key_x:, public_key_y:)
          return Packet.new(
            session_id: session_id,
            body: EncPacket.new(
              flags: 0,
              body: EncPacketInit.new(
                public_key_x: public_key_x,
                public_key_y: public_key_y,
              )
            )
          )
        end

        def self.create_enc_auth(session_id:, authenticator:)
          return Packet.new(
            session_id: session_id,
            body: EncPacket.new(
              flags: 0,
              body: EncPacketAuth.new(
                authenticator: authenticator,
              )
            )
          )
        end

        def to_bytes()
          return [@packet_id, @type, @session_id].pack("nCn") + @body.to_bytes()
        end

        def to_s()
          return "[0x%04x] session = 0x%04x :: %s" % [@packet_id, @session_id, @body.to_s()]
        end
      end
    end
  end
end
