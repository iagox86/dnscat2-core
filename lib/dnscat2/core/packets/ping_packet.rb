# Encoding: ASCII-8BIT
##
# ping_packet.rb
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
      class PingPacket
        # This gives us the verify_* functions
        extend PacketHelper

        attr_reader :options, :body

        TYPE = MESSAGE_TYPE_PING

        def initialize(options:, body:)
          @l = SingLogger.instance
          @l.debug("PingPacket: New instance! options = #{options}, body = #{body}")

          @options = options
          @body = body
        end

        def self.parse(options, data)
          SingLogger.instance.debug("PingPacket: Parsing #{data.length} bytes (options = #{options})")

          verify_nt!(data)
          body, data = data.unpack("Z*a*")
          verify_exactly!(data, 0)

          return self.new(
            options: options,
            body: body,
          )
        end

        def to_bytes()
          [@body].pack("Z*")
        end

        def to_s()
          return "[[PING]] :: body = %s" % [@body]
        end
      end
    end
  end
end
