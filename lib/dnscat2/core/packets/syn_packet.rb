##
# syn_packet.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

require 'dnscat2/core/packets/packet_helper'

module Dnscat2
  module Core
    module Packets
      class SynPacket
        extend PacketHelper

        attr_reader :isn, :name

        OPT_NAME                = 0x0001
        # OPT_TUNNEL              = 0x0002 # Deprecated
        # OPT_DATAGRAM            = 0x0004 # Deprecated
        # OPT_DOWNLOAD            = 0x0008 # Deprecated
        # OPT_CHUNKED_DOWNLOAD    = 0x0010 # Deprecated
        # OPT_COMMAND             = 0x0020 # Deprecated
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
