# Encoding: ASCII-8BIT
##
# packet_helper.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
#
# Helper functions for dnscat2 packets.
##

require 'dnscat2/core/dnscat_exception'

module Dnscat2
  module Core
    module Packets
      module PacketHelper
        def verify_length!(data, needed)
          if data.length < needed
            raise(DnscatException, "Failed to parse packet (too short or truncated)!")
          end
        end

        def verify_exactly!(data, needed)
          if data.length < needed
            raise(DnscatException, "Failed to parse packet (too short or truncated)!")
          end
          if data.length > needed
            raise(DnscatException, "Failed to parse packet (extra data was on the end)!")
          end
        end

        def verify_nt!(data)
          if data.index("\x00").nil?
            raise(DnscatException, "Missing null terminator!")
          end
        end

        def verify_not_null!(data, msg)
          if data.nil?
            raise(DnscatException, msg)
          end
        end
      end
    end
  end
end

