##
# enc_packet.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

require 'dnscat2/core/libs/crypto_helper'
require 'dnscat2/core/packets/packet_constants'
require 'dnscat2/core/packets/packet_helper'

module Dnscat2
  module Core
    module Packets
      class EncPacketInit
        extend PacketHelper
        attr_reader :public_key_x, :public_key_y

        def initialize(public_key_x:, public_key_y:)
          @public_key_x = public_key_x
          @public_key_y = public_key_y
        end

        def self.parse(data)
          exactly?(data, 64)
          public_key_x, public_key_y = data.unpack("a32a32")

          return self.new(
            public_key_x: CryptoHelper.binary_to_bignum(public_key_x),
            public_key_y: CryptoHelper.binary_to_bignum(public_key_y),
          )
        end

        def to_bytes()
          public_key_x = CryptoHelper.bignum_to_binary(@public_key_x)
          public_key_y = CryptoHelper.bignum_to_binary(@public_key_y)

          return [public_key_x, public_key_y].pack("a32a32")
        end

        def to_s()
          return "[[INIT]] :: pubkey = 0x%s,0x%s" % [CryptoHelper.bignum_to_text(@public_key_x), CryptoHelper.bignum_to_text(@public_key_y)]
        end
      end

      class EncPacketAuth
        extend PacketHelper
        attr_reader :authenticator

        def initialize(authenticator:)
          exactly?(authenticator, 32)
          @authenticator = authenticator
        end

        def self.parse(data)
          authenticator, data = data.unpack("a32a*")
          exactly?(data, 0)

          return self.new(
            authenticator: authenticator,
          )
        end

        def to_bytes()
          return [@authenticator].pack("a32")
        end

        def to_s()
          return "[[AUTH]] :: authenticator = %s" % [@authenticator.unpack("H*").pop()]
        end
      end

      class EncPacket
        # This gives us the verify_* functions
        extend PacketHelper

        attr_reader :subtype, :flags

        def initialize(subtype:, flags:, body:)
          if ![SUBTYPE_INIT, SUBTYPE_AUTH].include?(subtype)
            raise(DnscatException, "Illegal subtype on ENC packet")
          end

          @subtype = subtype
          @flags   = flags
          @body    = body
        end

        def self.parse(data)
          at_least?(data, 4)

          subtype, flags, data = data.unpack("nna*")

          if(subtype == SUBTYPE_INIT)
            exactly?(data, 64)
            body = EncPacketInit.parse(data)
          elsif(subtype == SUBTYPE_AUTH)
            exactly?(data, 32)
            body = EncPacketAuth.parse(data)
          else
            raise(DnscatException, "Unknown subtype: #{subtype}")
          end

          return self.new(
            subtype: subtype,
            flags: flags,
            body: body,
          )
        end

        def to_s()
          return "[[ENC]] :: flags = 0x%04x %s" % [@flags, @body.to_s]
        end

        def to_bytes()
          return [@subtype, @flags, @body.to_bytes].pack("nna*")
        end
      end
    end
  end
end

