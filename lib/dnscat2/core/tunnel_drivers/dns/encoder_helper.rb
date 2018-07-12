# Encoding: ASCII-8BIT
##
# encoder_helper.rb
# Created March, 2013
# By Ron Bowes
#
# See: LICENSE.md
##

require 'nesser'

require 'dnscat2/core/tunnel_drivers/dns/driver_dns_constants'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        module EncoderHelper
          public
          def double_check_length(rr:)
            packer = Nesser::Packer.new()
            rr.pack(packer)

            if(packer.get().length > MAX_RR_LENGTH)
              raise(DnscatException, "Tried to pack too much data into a name (packed #{packer.get().length} bytes, max is #{MAX_RR_LENGTH}! (This is an internal bug)")
            end
          end
        end
      end
    end
  end
end
