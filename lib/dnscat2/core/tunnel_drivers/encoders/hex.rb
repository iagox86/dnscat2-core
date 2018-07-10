# Encoding: ASCII-8BIT
##
# hex.rb
# Created March, 2018
# By Ron Bowes
#
# See: LICENSE.md
##

require 'dnscat2/core/dnscat_exception'

module Dnscat2
  module Core
    module TunnelDrivers
      module Encoders
        class Hex
          NAME = "Hex encoder"
          RATIO = 2.0
          DESCRIPTION = "Encodes to hex; for example, 'AAA' becomes '414141'. This is the simplest encoder (other than plaintext), but also the least efficient."
          CHARSET = /^[a-f0-9]*$/

          public
          def self.encode(data:)
            return data.unpack('H*').pop
          end

          public
          def self.decode(data:)
            if(data !~ CHARSET)
              raise(DnscatException, "Data isn't hex encoded!")
            end
            if((data.length % 2) != 0)
              raise(DnscatException, "Data isn't proper hex (it should have an even number of characters)!")
            end

            return [data].pack('H*')
          end
        end
      end
    end
  end
end
