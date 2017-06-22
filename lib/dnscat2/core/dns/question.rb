# Encoding: ASCII-8BIT
##
# question.rb
# Created June 21, 2017
# By Ron Bowes
#
# See: LICENSE.md
#
# This defines a DNS question. One question is sent in outgoing packets,
# and one question is also sent in the response - generally, the same as
# the question that was asked.
##
module DNSer
  class Question
    attr_reader :name, :type, :cls

    def initialize(name:, type:, cls:)
      @name  = name
      @type  = type
      @cls  = cls
    end

    def self.unpack(unpacker)
      name = unpacker.unpack_name()
      type, cls = unpacker.unpack("nn")

      return self.new(name: name, type: type, cls: cls)
    end

    def pack(packer)
      packer.pack_name(@name)
      packer.pack('nn', type, cls)
    end

    def to_s()
      return '%s [%s %s]' % [
        @name,
        TYPES[@type] || '<0x%04x?>' % @type,
        CLSES[@cls]  || '<0x%04x?>' % @cls,
      ]
    end

#    def answer(ttl, *args)
#      case @type
#      when TYPE_A
#        rr = A.new(*args)
#      when TYPE_NS
#        rr = NS.new(*args)
#      when TYPE_CNAME
#        rr = CNAME.new(*args)
#      when TYPE_MX
#        rr = MX.new(*args)
#      when TYPE_TXT
#        rr = TXT.new(*args)
#      when TYPE_AAAA
#        rr = AAAA.new(*args)
#      when TYPE_ANY
#        raise(FormatException, "We can't automatically create a response for an 'ANY' request :(")
#      else
#        raise(FormatException, "We don't know how to answer that type of request!")
#      end
#
#      return Answer.new(
#        name: @name,
#        type: @type,
#        cls: @cls,
#        ttl: ttl,
#        rr: rr,
#      )
#    end

#    def ==(other)
#      if(!other.is_a?(Question))
#        return false
#      end
#
#      return (@name == other.name) && (@type == other.type) && (@cls == other.cls)
#    end
  end
end
