# Encoding: ASCII-8BIT
##
# packer.rb
# Created June 20, 2017
# By Ron Bowes
#
# See: LICENSE.md
#
# DNS has some unusual properties that we have to handle, which is why I
# wrote this class. It handles building / parsing DNS packets and keeping
# track of where in the packet we currently are. The advantage, besides
# simpler unpacking, is that encoded names (with pointers to other parts
# of the packet) can be trivially handled.
##
module DNSer
  class DnsUnpacker
    attr_accessor :data

    # Create a new instance, initialized with the given data
    def initialize(data)
      @data = data.force_encoding("ASCII-8BIT")
      @offset = 0
    end

#      def remaining()
#        return @data[@offset..-1]
#      end

    # Unpack from the string, exactly like the normal `String#Unpack` method
    # in Ruby, except that an offset into the string is maintained and updated.
    def unpack(format, offset = nil)
      # If there's an offset, unpack starting there
      if(!offset.nil?)
        results = @data[offset..-1].unpack(format)
      else
        results = @data[@offset..-1].unpack(format + "a*")
        remaining = results.pop
        @offset = @data.length - remaining.length
      end

      if(!results.index(nil).nil?)
        raise(DNSer::Packet::FormatException, "DNS packet was truncated (or we messed up parsing it)!")
      end

      return *results
    end

    # This temporarily changes the offset that we're reading from, runs the
    # given block, then changes it back. This is used internally while
    # unpacking names.
    def _move_offset(offset)
      old_offset = @offset
      @offset = offset
      yield
      @offset = old_offset
    end

    # Unpack a name from the packet. Names are special, because they're
    # encoded as:
    # * A series of length-prefixed blocks, each indicating a segment
    # * Blocks with a length the starts with two '1' bits (11xxxxx...), which
    #   contains a pointer to another name elsewhere in the packet
    def unpack_name(depth = 0)
      segments = []

      if(depth > 16)
        raise(DNSer::Packet::FormatException, "It looks like this packet contains recursive pointers!")
      end

      loop do
        # If no offset is given, just eat data from the normal source
        len = unpack("C").pop()

        # Stop at the null terminator
        if(len == 0)
          break
        end
        # Handle "pointer" records by updating the offset
        if((len & 0xc0) == 0xc0)
          # If the first two bits are 1 (ie, 0xC0), the next
          # 10 bits are an offset, so we have to mask out the first two bits
          # with 0x3F (00111111)
          offset = ((len << 8) | unpack("C").pop()) & 0x3FFF

          _move_offset(offset) do
            segments << unpack_name(depth+1).split(/\./)
          end

          break
        end

        # It's normal, just unpack what we need to!
        segments << unpack("a#{len}")
      end

      return segments.join('.')
    end

    def verify_length(len)
      start_length = @offset
      yield
      end_length   = @offset

      if(end_length - start_length != len)
        raise(FormatException, "A resource record's length didn't match its actual length; something is funky")
      end
    end

    # Take a name, as a dotted string ("google.com") and return it as length-
    # prefixed segments ("\x06google\x03com\x00").
    #
    # TODO: Compress the name properly, if we can ("\xc0\x0c")
    def DnsUnpacker.pack_name(name)
      result = ''

      name.split(/\./).each do |segment|
        result += [segment.length(), segment].pack("Ca*")
      end

      result += "\0"
      return result
    end

    # Shows where in the string we're currently editing. Mostly usefulu for
    # debugging.
    def to_s()
      if(@offset == 0)
        return @data.unpack("H*").pop
      else
        return "#{@data[0..@offset-1].unpack("H*")}|#{@data[@offset..-1].unpack("H*")}"
      end
    end
  end
end
