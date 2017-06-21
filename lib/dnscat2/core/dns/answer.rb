# Encoding: ASCII-8BIT
##
# answer.rb
# Created June 20, 2017
# By Ron Bowes
#
# See: LICENSE.md
#
# A DNS answer. A DNS response packet contains zero or more Answer records
# (defined by the 'ancount' value in the header). An answer contains the
# name of the domain from the question, followed by a resource record.
##

module DNSer
  class Answer
    attr_reader :name, :type, :cls, :ttl, :rr

    def initialize(name:, type:, cls:, ttl:, rr:)
      @name = name
      @type = type
      @cls  = cls
      @ttl  = ttl
      @rr   = rr
    end

    def Answer.parse(unpacker)
      name = unpacker.unpack_name()
      type, cls, ttl, rr_length = unpacker.unpack("nnNn")

      case type
      when TYPE_A
        rr = A.parse(data)
      when TYPE_NS
        rr = NS.parse(data)
      when TYPE_CNAME
        rr = CNAME.parse(data)
      when TYPE_SOA
        rr = SOA.parse(data)
      when TYPE_MX
        rr = MX.parse(data)
      when TYPE_TXT
        rr = TXT.parse(data)
      when TYPE_AAAA
        rr = AAAA.parse(data)
      else
        puts("Warning: Unknown record type: #{type}")
        rr = RRUnknown.parse(type, data, rr_length)
      end

      return Answer.new(
        name: name,
        type: type,
        cls: cls,
        ttl: ttl,
        rr: rr,
      )
    end

    def pack(packer)
      packer.pack_name(@name)

      # We don't actually know what the length is till after we pack a record,
      # so use 0x1337 as a placeholder
      packer.pack('nnNn', @type, @cls, @ttl)
      @rr.pack(packer)
    end

    def to_s()
      return '%s [%s %s]' % [
        @name,
        TYPES[@type] || '<0x%04x?>' % @type,
        CLSES[@cls]  || '<0x%04x?>' % @cls,
      ]
    end
  end
end
