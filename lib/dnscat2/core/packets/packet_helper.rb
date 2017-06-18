##
# packet_helper.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
#
# Helper functions for dnscat2 packets.
##

require 'dnscat2/core/libs/dnscat_exception'

module Dnscat2
  module Core
    module Packets
      module PacketHelper
        def at_least?(data, needed)
          if data.length < needed
            raise(DnscatException, "Failed to parse packet (too short or truncated)!")
          end
        end

        def exactly?(data, needed)
          if data.length < needed
            raise(DnscatException, "Failed to parse packet (too short or truncated)!")
          end
          if data.length > needed
            raise(DnscatException, "Failed to parse packet (extra data was on the end)!")
          end
        end

        def has_null_terminator?(data)
          if data.index("\x00").nil?
            raise(DnscatException, "Missing null terminator!")
          end
        end
      end
    end
  end
end

