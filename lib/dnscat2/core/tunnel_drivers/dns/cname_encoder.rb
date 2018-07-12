# Encoding: ASCII-8BIT
##
# cname_encoder.rb
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
require 'dnscat2/core/tunnel_drivers/dns/name_helper'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class CNAMEEncoder < NameHelper
          public
          def initialize(tag:, domain:, max_subdomain_length: 63, encoder: Encoders::Hex)
            super(tag:tag, domain:domain, max_subdomain_length: max_subdomain_length, encoder: encoder)

            @l = SingLogger.instance()
          end

          ##
          # Gets a string of data, no longer than max_length().
          #
          # Returns a resource record of the correct type.
          ##
          public
          def encode(data:)
            @l.debug("TunnelDrivers::DNS::CNAMEEncoder Encoding #{data.length} bytes of data")

            name = encode_name(data: data)

            # Create the RR with a random preference
            return Nesser::CNAME.new(name: name)
          end
        end
      end
    end
  end
end
