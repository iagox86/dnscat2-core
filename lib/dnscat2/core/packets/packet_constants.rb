##
# packet_constants.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
#
# Constants for dnscat2 packets.
##

module Dnscat2
  module Core
    module Packet
      # Message types
      MESSAGE_TYPE_SYN        = 0x00
      MESSAGE_TYPE_MSG        = 0x01
      MESSAGE_TYPE_FIN        = 0x02
      MESSAGE_TYPE_PING       = 0xFF
      MESSAGE_TYPE_ENC        = 0x03

      # Sub-messages for MESSAGE_TYPE_ENC
      SUBTYPE_INIT = 0x0000
      SUBTYPE_AUTH = 0x0001
    end
  end
end
