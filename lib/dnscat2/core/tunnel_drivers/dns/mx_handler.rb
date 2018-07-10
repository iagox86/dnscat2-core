# Encoding: ASCII-8BIT
##
# mx_handler.rb
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
        class MXHandler
          public
          def initialize(tag:, domain:, max_subdomain_length: 63)
            @l = SingLogger.instance()
            @tag = tag
            @domain = domain
            @max_subdomain_length = max_subdomain_length

            if(@max_subdomain_length < 1 || @max_subdomain_length > 63)
              raise(Dnscat2Exception, "max_subdomain_length is not sane")
            end
          end

          ##
          # The maximum length of data that can be encoded, including pre- or
          # appending tags and domain names.
          ##
          public
          def max_length()
            # First, calculate how many periods we will need in the absolute
            # worst case - the logic is:
            # subdomain_length = 1, 1/2 are periods
            # subdomain_length = 2, 1/3 are periods
            # subdomain_length = 3, 1/4 are periods
            # ...etc, which is why we add 1
            number_of_periods = (MAX_RR_LENGTH / (@max_subdomain_length + 1))

            # Exclude the "wasted space"
            max_length = MAX_RR_LENGTH - number_of_periods

            # Subtract the length of tag or domain (these shouldn't both be set,
            # but this library doesn't really care)
            if(@tag)
              max_length = max_length - (@tag.length + 1)
            end
            if(@domain)
              max_length = max_length - (@domain.length + 1)
            end

            # Halve the length, for encoding
            return (max_length / 2)
          end

          ##
          # Gets a string of data, no longer than max_length().
          #
          # Returns a resource record of the correct type.
          ##
          public
          def encode(data:)
            @l.debug("TunnelDrivers::DNS::MXHandler Encoding #{data.length} bytes of data")

            # Prepend a tag if it exists
            if(@tag)
              name = "#{@tag}.#{name}"
            end

            # Append a domain if it exists
            if(@domain)
              name = "#{name}.#{@domain}"
            end

            # Sanity check
            if(data.length > max_length)
              raise(DnscatException, "Tried to encode too much data!")
            end

            # Split the name into 63-character segments and put them back together
            name = data.unpack("H*").pop.chars.each_slice(63).map(&:join).join(".")

            # Always double check that we aren't too big for a DNS packet
            if(name.length > 254)
              raise(DnscatException, "Tried to encode a name that's too long for the protocol")
            end

            # Create the RR with a random preference
            return Nesser::MX.new(name: name, preference: [10, 20, 30, 40, 50].sample)
          end
        end
      end
    end
  end
end
