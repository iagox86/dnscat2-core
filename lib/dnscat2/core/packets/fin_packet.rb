##
# fin_packet.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

module Dnscat2
  module Core
    module Packets
      class FinPacket
        attr_reader :reason

        def initialize(options, params = {})
          @options = options
          @reason = params[:reason] || raise(ArgumentError, "params[:reason] can't be nil!")
        end

        def FinBody.parse(options, data)
          at_least?(data, 1) || raise(DnscatException, "Packet is too short (FIN)")

          reason = data.unpack("Z*").pop
          data = data[(reason.length+1)..-1]

          if(data.length > 0)
            raise(DnscatException, "Extra data on the end of a FIN packet")
          end

          return FinBody.new(options, {
            :reason => reason,
          })
        end

        def to_s()
          return "[[FIN]] :: %s" % [@reason]
        end

        def to_bytes()
          [@reason].pack("Z*")
        end
      end
    end
  end
end

