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

    def self.parse(unpacker)
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
#        record = A.new(*args)
#      when TYPE_NS
#        record = NS.new(*args)
#      when TYPE_CNAME
#        record = CNAME.new(*args)
#      when TYPE_MX
#        record = MX.new(*args)
#      when TYPE_TXT
#        record = TXT.new(*args)
#      when TYPE_AAAA
#        record = AAAA.new(*args)
#      when TYPE_ANY
#        raise(FormatException, "We can't automatically create a response for an 'ANY' request :(")
#      else
#        raise(FormatException, "We don't know how to answer that type of request!")
#      end
#
#      return Answer.new(@name, @type, @cls, ttl, record)
#    end
#
#    def ==(other)
#      if(!other.is_a?(Question))
#        return false
#      end
#
#      return (@name == other.name) && (@type == other.type) && (@cls == other.cls)
#    end
  end
end
