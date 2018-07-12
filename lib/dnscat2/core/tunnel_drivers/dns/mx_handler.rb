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
require 'dnscat2/core/tunnel_drivers/dns/name_helper'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class MXHandler < NameHelper
          # The 'preference' field of the MX packet takes up 2 bytes
          EXTRA_BYTES = 2

          public
          def initialize(tag:, domain:, max_subdomain_length: 63, encoder: Encoders::Hex)
            super(tag:tag, domain:domain, max_subdomain_length: max_subdomain_length, encoder: encoder, extra_bytes: EXTRA_BYTES)

            @l = SingLogger.instance()
          end

          ##
          # Gets a string of data, no longer than max_length().
          #
          # Returns a resource record of the correct type.
          ##
          public
          def encode(data:)
            @l.debug("TunnelDrivers::DNS::MXHandler Encoding #{data.length} bytes of data")

            name = encode_name(data: data)

            # Create the RR with a random preference
            return Nesser::MX.new(name: name, preference: [10, 20, 30, 40, 50].sample)
          end
        end
      end
    end
  end
end
