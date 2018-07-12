# Encoding: ASCII-8BIT
##
# txt_encoder.rb
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
require 'dnscat2/core/tunnel_drivers/encoders/hex'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class TXTEncoder
          include EncoderHelper

          public
          def initialize(tag:, domain:, encoder:Encoders::Hex)
            @l = SingLogger.instance()
            @tag = tag
            @domain = domain
            @encoder = encoder
          end

          ##
          # The maximum length of data that can be encoded, including pre- or
          # appending tags and domain names.
          ##
          public
          def max_length()
            # -3 for the length prefixes (two bytes, then one byte)
            return ((MAX_RR_LENGTH - 3) / @encoder::RATIO).floor
          end

          ##
          # Gets a string of data, no longer than max_length().
          #
          # Returns a resource record of the correct type.
          ##
          public
          def encode(data:)
            @l.debug("TunnelDrivers::DNS::TXTEncoder Encoding #{data.length} bytes of data")
            if(data.length > max_length)
              raise(DnscatException, "Tried to encode too much data!")
            end

            # Note: we still encode TXT records, because some OSes have trouble
            # with null-bytes in TXT records (I'm looking at you, Windows)
            data = @encoder.encode(data: data)

            # Always double check that we aren't too big for a DNS packet
            rr = Nesser::TXT.new(data: data)
            double_check_length(rrs: [rr])
            return [rr]
          end
        end
      end
    end
  end
end
