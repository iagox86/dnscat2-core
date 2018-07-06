# Encoding: ASCII-8BIT
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

        TYPE = MESSAGE_TYPE_SYN

        def initialize(isn:, name:nil)
          @isn = isn
          @name = name
        end

        def self.parse(data)
          # Body
          # (uint16_t) initial sequence number
          # (uint16_t) options
          verify_length!(data, 4)
          isn, options, data = data.unpack('nna*')

          # If OPT_NAME is set:
          #   (ntstring) session_name
          if((options & OPT_NAME) == OPT_NAME)
            verify_nt!(data)
            name, data = data.unpack("Z*a*")
          end

          # Make sure there's no hanging data
          verify_exactly!(data, 0)

          return self.new(
            isn: isn,
            name: name,
          )
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

        def to_s()
          return "[[SYN]] :: isn = 0x%04x, name = %s" % [@isn, @name || '(n/a)']
        end
      end
    end
  end
end
