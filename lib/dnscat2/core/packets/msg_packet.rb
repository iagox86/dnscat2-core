# Encoding: ASCII-8BIT
##
# msg_packet.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

require 'singlogger'

require 'dnscat2/core/packets/packet_constants'
require 'dnscat2/core/packets/packet_helper'

module Dnscat2
  module Core
    module Packets
      class MsgPacket
        # This gives us the verify_* functions
        extend PacketHelper

        attr_reader :options, :seq, :ack, :data

        TYPE = MESSAGE_TYPE_MSG

        def initialize(options:, seq:, ack:, data:)
          @l = SingLogger.instance
          @l.debug("MsgPacket: New instance! options = #{options}, seq = #{seq}, ack = #{ack}, data = #{data}")

          @options = options
          @seq = seq
          @ack = ack
          @data = data
        end

        def self.parse(options, data)
          SingLogger.instance.debug("MsgPacket: Parsing #{data.length} bytes of data! (options = #{options})")

          verify_length!(data, 4)

          seq, ack, data = data.unpack("nna*")

          return self.new(
            options: options,
            seq: seq,
            ack: ack,
            data: data,
          )
        end

        def to_bytes()
          return [@seq, @ack, @data].pack("nna*")
        end

        def to_s()
          return "[[MSG]] :: seq = 0x%04x, ack = 0x%04x, data = (0x%x bytes)" % [@seq, @ack, @data.length]
        end
      end
    end
  end
end

