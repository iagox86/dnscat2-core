# Encoding: ASCII-8BIT
##
# enc_packet.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

require 'singlogger'

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
          @l = SingLogger.instance()
          @l.debug("EncPacketInit: New instance! public_key_x = #{public_key_x}, public_key_y = #{public_key_y}")

          @public_key_x = public_key_x
          @public_key_y = public_key_y
        end

        def self.parse(data)
          SingLogger.instance().debug("EncPacketInit: Parsing a #{data.length}-byte packet")

          verify_exactly!(data, 64)
          public_key_x, public_key_y = data.unpack("a32a32")

          return self.new(
            public_key_x: Libs::CryptoHelper.binary_to_bignum(public_key_x),
            public_key_y: Libs::CryptoHelper.binary_to_bignum(public_key_y),
          )
        end

        def to_bytes()
          public_key_x = Libs::CryptoHelper.bignum_to_binary(@public_key_x)
          public_key_y = Libs::CryptoHelper.bignum_to_binary(@public_key_y)

          return [public_key_x, public_key_y].pack("a32a32")
        end

        def to_s()
          return "[[INIT]] :: pubkey = 0x%s,0x%s" % [Libs::CryptoHelper.bignum_to_text(@public_key_x), Libs::CryptoHelper.bignum_to_text(@public_key_y)]
        end
      end

      class EncPacketAuth
        extend PacketHelper
        attr_reader :authenticator

        def initialize(authenticator:)
          @l = SingLogger.instance()
          @l.debug("EncPacketAuth: New instance! authenticator = #{authenticator}")

          @authenticator = authenticator
        end

        def self.parse(data)
          SingLogger.instance().debug("EncPacketAuth: parsing #{data.length} bytes of data")

          verify_exactly!(data, 32)
          authenticator = data.unpack("a32").pop

          return self.new(
            authenticator: Libs::CryptoHelper.binary_to_bignum(authenticator),
          )
        end

        def to_bytes()
          authenticator = Libs::CryptoHelper.bignum_to_binary(@authenticator)

          return [authenticator].pack("a32")
        end

        def to_s()
          return "[[AUTH]] :: authenticator = 0x%s" % [Libs::CryptoHelper.bignum_to_text(@authenticator)]
        end
      end

      class EncPacket
        # This gives us the verify_* functions
        extend PacketHelper
        attr_reader :subtype, :flags, :body

        TYPE = MESSAGE_TYPE_ENC

        def initialize(flags:, body:)
          @l = SingLogger.instance()
          @l.debug("EncPacket: New instance! flags = #{flags}, body = #{body}")

          if body.is_a?(EncPacketInit)
            @subtype = SUBTYPE_INIT
          elsif body.is_a?(EncPacketAuth)
            @subtype = SUBTYPE_AUTH
          else
            raise(DnscatException, "Illegal subtype on ENC packet")
          end

          @flags   = flags
          @body    = body
        end

        def self.parse(data)
          SingLogger.instance().debug("EncPacket: parsing #{data.length} bytes of data")

          verify_length!(data, 4)

          subtype, flags, data = data.unpack("nna*")

          case subtype
          when SUBTYPE_INIT
            verify_exactly!(data, 64)
            body = EncPacketInit.parse(data)
          when SUBTYPE_AUTH
            verify_exactly!(data, 32)
            body = EncPacketAuth.parse(data)
          else
            raise(DnscatException, "Unknown subtype: #{subtype}")
          end

          return self.new(
            flags: flags,
            body: body,
          )
        end

        def to_bytes()
          return [@subtype, @flags, @body.to_bytes].pack("nna*")
        end

        def to_s()
          return "[[ENC]] :: flags = 0x%04x %s" % [@flags, @body.to_s]
        end
      end
    end
  end
end

