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
require 'dnscat2/core/tunnel_drivers/dns/encoder_helper'
require 'dnscat2/core/tunnel_drivers/dns/name_helper'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class CNAMEEncoder < NameHelper
          include EncoderHelper

          public
          def initialize(tag:, domain:, max_subdomain_length: 63, encoder: Encoders::Hex)
            # CNAME has 4 extra bytes: the 2-byte length field
            super(tag:tag, domain:domain, max_subdomain_length: max_subdomain_length, encoder: encoder, extra_bytes: 2)

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

            # Create the RR
            rr = Nesser::CNAME.new(name: name)
            double_check_length(rrs: [rr])
            return [rr]
          end
        end
      end
    end
  end
end
