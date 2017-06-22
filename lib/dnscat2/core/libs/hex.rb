# Encoding: ASCII-8BIT
##
# hex.rb
# Created November, 2012
# By Ron Bowes
#
# See: LICENSE.md
#
# This is a simple utility class that converts an arbitrary binary string into
# a user-readable string.
##

module Dnscat2
  module Core
    class Hex
      BYTE_NUMBER_LENGTH  = 8
      SPACES_BEFORE_HEX   = 2
      SPACES_BEFORE_ASCII = 2
      LINE_LENGTH         = 16

      # Convert the arbitrary binary data, 'data', into a user-readable string.
      def Hex.to_s(data, indent: 0, offset: nil)
        length = data.length
        out = (' ' * indent)

        0.upto(length - 1) do |i|
          # This section encodes all the hex lines, including the final partial line
          if((i % LINE_LENGTH) == 0)
            if(i != 0)
              # Subtract one from the indent because we print a space surrounding
              # the actual hex number
              out = out + "\n" + (' ' * indent)
            end
            # Minus 1, so we can potentially replace the last one with a current-
            # place marker
            out = out + ("%0#{BYTE_NUMBER_LENGTH}x" % i) + " " * (SPACES_BEFORE_HEX - 1)
            if(offset && (i == offset))
              out = out + '<'
            else
              out = out + ' '
            end
          end

          out = out + ("%02x" % data[i].ord)
          # Always put a '>' immediately after the highlighted offset
          if(i == offset)
            out = out + '>'
          # Put a '>' after the value before the chosen offset, unless we're at
          # the end of a line or the absolute end
          elsif((i + 1 == offset) && (((i + 1) % LINE_LENGTH) != 0) && ((i + 1) % length) != 0)
            out = out + '<'
          else
            out = out + ' '
          end

          if(((i + 1) % LINE_LENGTH) == 0)
            out = out + (" " * SPACES_BEFORE_ASCII)
            LINE_LENGTH.step(1, -1) do |j|
              out = out + ("%c" % ((data[i + 1 - j].ord > 0x20 && data[i + 1 - j].ord < 0x80) ? data[i + 1 - j].ord : ?.))
            end
          end

        end

        # This encodes the partial line of ascii, plus the spaces before
        if((length % LINE_LENGTH) != 0)
          # Add extra spaces between the hex and the ascii
          (length % LINE_LENGTH).upto(LINE_LENGTH - 1) do |i|
            out = out + ('   ') # The width of a hex character and a space
          end
          out = out + (' ' * SPACES_BEFORE_ASCII)

          # Add the final line of characters
          (length - (length % LINE_LENGTH)).upto(length - 1) do |i|
            out = out + ("%c" % ((data[i].ord > 0x20 && data[i].ord < 0x80) ? data[i].ord : ?.))
          end
        end

        return out
      end
    end
  end
end
