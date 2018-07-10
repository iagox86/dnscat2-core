# Encoding: ASCII-8BIT
##
# txt_handler.rb
# Created March, 2013
# By Ron Bowes
#
# See: LICENSE.md
##

require 'nesser'
require 'singlogger'
require 'thread'

require 'dnscat2/core/dnscat_exception'

require 'dnscat2/core/tunnel_drivers/dns/driver_dns_constants'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class TXTHandler
          APPEND_DOMAIN = false # TODO: Remove
          MAX_LENGTH = 254 # TODO: Remove

          public
          def initialize(tag:, domain:)
            @l = SingLogger.instance()
            @tag = tag
            @domain = domain
          end

          ##
          # The maximum length of data that can be encoded, including pre- or
          # appending tags and domain names.
          ##
          public
          def max_length()
            return (254 / 2)
          end

          ##
          # Gets a string of data, no longer than max_length().
          #
          # Returns a resource record of the correct type.
          ##
          public
          def encode(data:)
            @l.debug("TunnelDrivers::DNS::TXTHandler Encoding #{data.length} bytes of data")
            if(data.length > max_length)
              raise(DnscatException, "Tried to encode too much data!")
            end

            # Note: we still encode TXT records, because some OSes have trouble
            # with null-bytes in TXT records (I'm looking at you, Windows)
            data = data.unpack("H*").pop

            # Always double check that we aren't too big for a DNS packet
            if(data.length > 254)
              raise(DnscatException, "Tried to encode a name that's too long for the protocol")
            end

            return Nesser::TXT.new(data: data)
          end
        end
      end
    end
  end
end
