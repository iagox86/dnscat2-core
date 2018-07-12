# Encoding: ASCII-8BIT
##
# driver_dns_constants.rb
# Created March, 2013
# By Ron Bowes
#
# See: LICENSE.md
##

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        MAX_RR_LENGTH = 253

        MAX_A_RECORDS = 64
        MAX_AAAA_RECORDS = 16
        NAME = "DNS Listener"
      end
    end
  end
end
