# Encoding: ASCII-8BIT
##
# aaaa.rb
# Created July, 2018
# By Ron Bowes
#
# See: LICENSE.md
##

require 'nesser'
require 'singlogger'
require 'thread'

require 'dnscat2/core/dnscat_exception'
require 'dnscat2/core/tunnel_drivers/dns/builders/builder_helper'
require 'dnscat2/core/tunnel_drivers/dns/driver_dns_constants'
require 'dnscat2/core/tunnel_drivers/encoders/hex'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        module Builders
          class AAAA
            include BuilderHelper

            public
            def initialize(tag:, domain:, encoder:Encoders::Hex)
              # We don't bother saving any of the parameters, they aren't
              # necessary

              @l = SingLogger.instance()
            end

            ##
            # The maximum amount of data that can be recorded
            ##
            public
            def max_length()
              # We can fit 2 bytes in the first ip address, then 3 bytes in the
              # remaining ones
              number_of_ips = MAX_RR_LENGTH / 16
              return 14 + ((number_of_ips - 1) * 15)
            end

            ##
            # Gets a string of data, no longer than max_length().
            #
            # Returns a resource record of the correct type.
            ##
            public
            def build(data:)
              @l.debug("TunnelDrivers::DNS::Builders::AAAA Encoding #{data.length} bytes of data")
              if(data.length > max_length)
                raise(DnscatException, "Tried to encode too much data!")
              end

              if(data.length > 255)
                raise(DnscatException, "Tried to encode more than 255 bytes of data!")
              end

              # Prefix with length
              data = [data.length, data].pack('Ca*')

              # Break into 15-byte blocks, so we can prepend a sequence number to
              # each
              i = 0
              data = data.chars.each_slice(15).map(&:join).map do |ip|
                ip = [i] + ip.ljust(15, "\xFF").bytes()
                i += 1

                ip.each_slice(2).map() do |octet|
                  "%02x%02x" % [octet[0], octet[1]]
                end.join(":") # return
               end

              return data.map() do |ip|
                Nesser::AAAA.new(address: ip)
              end
            end
          end
        end
      end
    end
  end
end
