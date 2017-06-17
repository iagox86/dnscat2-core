##
# syn_packet.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

module Dnscat2
  module Core
    module Packet
      class PingPacket
        attr_reader :data

        def initialize(options, params = {})
          @options = options
          @data = params[:data] || raise(ArgumentError, "params[:data] can't be nil!")
        end

        def PingBody.parse(options, data)
          at_least?(data, 3) || raise(DnscatException, "Packet is too short (PING)")

          data = data.unpack("Z*").pop

          return PingBody.new(options, {
            :data => data,
          })
        end

        def to_s()
          return "[[PING]] :: %s" % [@data]
        end

        def to_bytes()
          [@data].pack("Z*")
        end
      end
    end
  end
end
