##
# syn_packet.rb
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
      class SynPacket
        # This gives us the verify_* functions
        extend PacketHelper

        attr_reader :isn, :name

        def initialize(isn:, name:nil)
          @isn = isn
          @name = name
        end

        def to_bytes()
          result = ''

          # Initial sequence number
          result += [@isn].pack('n')

          # Options
          if(@name.nil?)
            result += [0].pack('n')
          else
            result += [OPT_NAME].pack('n')
            result += [@name].pack('Z*')
          end

          return result
        end

        def self.parse(data)
          # Body
          # (uint16_t) initial sequence number
          # (uint16_t) options
          at_least?(data, 4)
          isn, options, data = data.unpack('nna*')

          # If OPT_NAME is set:
          #   (ntstring) session_name
          if((options & OPT_NAME) == OPT_NAME)
            has_null_terminator?(data)
            name, data = data.unpack("Z*a*")
          end

          # Make sure there's no hanging data
          exactly?(data, 0)

          return SynPacket.new(
            isn: isn,
            name: name,
          )
        end
      end
    end
  end
end
