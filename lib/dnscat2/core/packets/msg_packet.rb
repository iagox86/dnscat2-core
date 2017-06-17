##
# msg_packet.rb
# Created June, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

module Dnscat2
  module Core
    module Packet
      class MsgPacket
        attr_reader :seq, :ack, :data

        def initialize(options, params = {})
          @options = options
          @seq = params[:seq] || raise(ArgumentError, "params[:seq] can't be nil!")
          @ack = params[:ack] || raise(ArgumentError, "params[:ack] can't be nil!")
          @data = params[:data] || raise(ArgumentError, "params[:data] can't be nil!")
        end

        def MsgBody.parse(options, data)
          at_least?(data, 4) || raise(DnscatException, "Packet is too short (MSG norm)")

          seq, ack = data.unpack("nn")
          data = data[4..-1] # Remove the first four bytes

          return MsgBody.new(options, {
            :seq   => seq,
            :ack   => ack,
            :data  => data,
          })
        end

        def MsgBody.header_size(options)
          return MsgBody.new(options, {
            :seq   => 0,
            :ack   => 0,
            :data  => '',
          }).to_bytes().length()
        end

        def to_s()
          return "[[MSG]] :: seq = %04x, ack = %04x, data = 0x%x bytes" % [@seq, @ack, data.length]
        end

        def to_bytes()
          result = ""
          seq = @seq || 0
          ack = @ack || 0
          result += [seq, ack, @data].pack("nna*")

          return result
        end
      end
    end
  end
end

