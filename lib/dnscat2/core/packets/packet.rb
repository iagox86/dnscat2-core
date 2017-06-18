##
# packet.rb
# Created March, 2013
# By Ron Bowes
#
# See: LICENSE.md
#
# Builds and parses dnscat2 packets.
##

require 'dnscat2/core/libs/dnscat_exception'
require 'dnscat2/core/libs/hex'

module Dnscat2
  module Core
    module Packets
      include PacketHelper

      class Packet
        attr_reader :packet_id, :type, :session_id, :body

        private
        def initialize(packet_id:, type:, session_id:, body:)
          not_null?(type, "`type` can't be nil!")

          @packet_id  = packet_id  || rand(0xFFFF)
          @type       = type       || raise(ArgumentError, "type can't be nil!")
          @session_id = session_id || raise(ArgumentError, "session_id can't be nil!")
          @body       = body
        end

        private
        def self.parse_header(data)
          at_least?(data, 5) || raise(DnscatException, "Packet is too short (header)")

          # (uint16_t) packet_id
          # (uint8_t)  message_type
          # (uint16_t) session_id
          packet_id, type, session_id = data.unpack("nCn")
          data = data[5..-1]

          return packet_id, type, session_id, data
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
        def self.parse(data, options: {})
          packet_id, type, session_id, data = Packet.parse_header(data)

          case type
          when MESSAGE_TYPE_SYN
            body = SynPacket.parse(data)
          when MESSAGE_TYPE_MSG
            not_null?(options, "`options` is required when parsing a MSG packet!")
            body = MsgPacket.parse(options: options, data: data)
          when MESSAGE_TYPE_FIN
            not_null?(options, "`options` is required when parsing a FIN packet!")
            body = FinPacket.parse(options, data)
          when MESSAGE_TYPE_PING
            body = PingPacket.parse(nil, data)
          when MESSAGE_TYPE_ENC
            body = EncPacket.parse(data)
          else
            raise(DnscatException, "Unknown message type: 0x%x" % type)
          end

          return Packet.new(packet_id: packet_id, type: type, session_id: session_id, body: body)
        end

        def self.create_syn(options:, isn:, name:nil)
          return Packet.new(
            packet_id: params[:packet_id],
            type: MESSAGE_TYPE_SYN,
            session_id: params[:session_id],
            body: SynPacket.new(options: options, isn: isn, name: name)
          )
        end

        def self.create_msg(options, params = {})
          return Packet.new(
            params[:packet_id],
            MESSAGE_TYPE_MSG,
            params[:session_id],
            MsgPacket.new(options, params)
          )
        end

        def self.create_fin(options, params = {})
          return Packet.new(
            params[:packet_id],
            MESSAGE_TYPE_FIN,
            params[:session_id],
            FinBody.new(options, params)
          )
        end

        def self.create_ping(params = {})
          return Packet.new(
            params[:packet_id],
            MESSAGE_TYPE_PING,
            params[:session_id],
            PingBody.new(nil, params)
          )
        end

        def self.create_enc(params = {})
          return Packet.new(
            params[:packet_id],
            MESSAGE_TYPE_ENC,
            params[:session_id],
            EncBody.new(params)
          )
        end

        def to_s()
          return "[0x%04x] session = %04x :: %s" % [@packet_id, @session_id, @body.to_s]
        end

        def to_bytes()
          return [@packet_id, @type, @session_id].pack("nCn") + @body.to_bytes()
        end
      end
    end
  end
end
