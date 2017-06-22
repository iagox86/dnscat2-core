# Encoding: ASCII-8BIT
##
# fin_packet.rb
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
      class FinPacket
        # This gives us the verify_* functions
        extend PacketHelper

        attr_reader :options, :reason

        def initialize(options:, reason:)
          @options = options
          @reason = reason
        end

        def self.parse(options, data)
          verify_nt!(data)
          reason, data = data.unpack("Z*a*")
          verify_exactly!(data, 0)

          return self.new(
            options: options,
            reason: reason,
          )
        end

        def to_bytes()
          [@reason].pack("Z*")
        end

        def to_s()
          return "[[FIN]] :: reason = %s" % [@reason]
        end
      end
    end
  end
end

