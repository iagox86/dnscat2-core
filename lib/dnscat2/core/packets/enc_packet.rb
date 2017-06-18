##
# enc_packet.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

module Dnscat2
  module Core
    module Packets
      class EncPacket
        attr_reader :subtype, :flags
        attr_reader :public_key_x, :public_key_y # SUBTYPE_INIT
        attr_reader :authenticator # SUBTYPE_AUTH

        def initialize(params = {})
          @subtype = params[:subtype] || raise(ArgumentError, "params[:subtype] is required!")
          @flags   = params[:flags]   || raise(ArgumentError, "params[:flags] is required!")

          if(@subtype == SUBTYPE_INIT)
            @public_key_x = params[:public_key_x] || raise(ArgumentError, "params[:public_key_x] is required!")
            @public_key_y = params[:public_key_y] || raise(ArgumentError, "params[:public_key_y] is required!")

            if(!@public_key_x.is_a?(Bignum) || !@public_key_y.is_a?(Bignum))
              raise(ArgumentError, "Public keys have to be Bignums! (Seen: #{@public_key_x.class} #{@public_key_y.class})")
            end
          elsif(@subtype == SUBTYPE_AUTH)
            @authenticator = params[:authenticator] || raise(ArgumentError, "params[:authenticator] is required!")

            if(@authenticator.length != 32)
              raise(ArgumentError, "params[:authenticator] was the wrong size!")
            end
          else
            raise(ArgumentError, "Unknown subtype: #{@subtype}")
          end
        end

        def EncBody.parse(data)
          at_least?(data, 4) || raise(DnscatException, "ENC packet is too short!")

          subtype, flags, data = data.unpack("nna*")

          params = {
            :subtype => subtype,
            :flags   => flags,
          }

          if(subtype == SUBTYPE_INIT)
            exactly?(data, 64) || raise(DnscatException, "ENC packet is too short!")

            public_key_x, public_key_y, data = data.unpack("a32a32a*")

            params[:public_key_x] = CryptoHelper.binary_to_bignum(public_key_x)
            params[:public_key_y] = CryptoHelper.binary_to_bignum(public_key_y)

          elsif(subtype == SUBTYPE_AUTH)
            exactly?(data, 32) || raise(DnscatException, "ENC packet is too short!")

            authenticator, data = data.unpack("a32a*")

            params[:authenticator] = authenticator
          else
            raise(DnscatException, "Unknown subtype: #{subtype}")
          end

          if(data != "")
            raise(DnscatException, "Extra data on the end of an ENC packet")
          end

          return EncBody.new(params)
        end

        def to_s()
          if(@subtype == SUBTYPE_INIT)
            return "[[ENC|INIT]] :: flags = 0x%04x, pubkey = %s,%s" % [@flags, CryptoHelper.bignum_to_text(@public_key_x), CryptoHelper.bignum_to_text(@public_key_y)]
          elsif(@subtype == SUBTYPE_AUTH)
            return "[[ENC|AUTH]] :: flags = 0x%04x, authenticator = %s" % [@flags, @authenticator.unpack("H*").pop()]
          else
            raise(DnscatException, "Unknown subtype: #{@subtype}")
          end
        end

        def to_bytes()
          if(@subtype == SUBTYPE_INIT)
            public_key_x = CryptoHelper.bignum_to_binary(@public_key_x)
            public_key_y = CryptoHelper.bignum_to_binary(@public_key_y)

            return [@subtype, @flags, public_key_x, public_key_y].pack("nna32a32")
          elsif(@subtype == SUBTYPE_AUTH)
            return [@subtype, @flags, @authenticator].pack("nna32")
          else
            raise(DnscatException, "Unknown subtype: #{@subtype}")
          end
        end
      end
    end
  end
end

