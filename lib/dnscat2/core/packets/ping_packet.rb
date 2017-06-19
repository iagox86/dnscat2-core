# Encoding: ASCII-8BIT
##
# ping_packet.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

require 'dnscat2/core/packets/packet_constants'
require 'dnscat2/core/packets/packet_helper'

module Dnscat2
  module Core
    module Packets
      class PingPacket
        # This gives us the verify_* functions
        extend PacketHelper

        attr_reader :options, :body

        def initialize(options:, body:)
          @options = options
          @body = body
        end

        def self.parse(options, data)
          has_null_terminator?(data)
          body, data = data.unpack("Z*a*")
          exactly?(data, 0)

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
