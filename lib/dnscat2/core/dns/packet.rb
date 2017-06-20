# Encoding: ASCII-8BIT
##
# packet.rb
# Created June 20, 2017
# By Ron Bowes
#
# See: LICENSE.md
##
module DNSer
  class Packet

    attr_accessor :trn_id, :opcode, :flags, :rcode, :questions, :answers

    # This defines a DNS question. One question is sent in outgoing packets,
    # and one question is also sent in the response - generally, the same as
    # the question that was asked.
    class Question
      attr_reader :name, :type, :cls

      def initialize(name, type = DNSer::Packet::TYPE_ANY, cls = DNSer::Packet::CLS_IN)
        @name  = name
        @type  = type
        @cls  = cls
      end

      def Question.parse(data)
        name = data.unpack_name()
        type, cls = data.unpack("nn")

        return Question.new(name, type, cls)
      end

      def serialize()
        return [DNSer::Packet::DnsUnpacker.pack_name(@name), type, cls].pack("a*nn")
      end

      def type_s()
        return DNSer::Packet::TYPES[@type] || "<unknown>"
      end

      def cls_s()
        return DNSer::Packet::CLSES[@cls] || "<unknown>"
      end

      def to_s()
        return "#{name} [#{type_s()} #{cls_s()}]"
      end

      def answer(ttl, *args)
        case @type
        when DNSer::Packet::TYPE_A
          record = DNSer::Packet::A.new(*args)
        when DNSer::Packet::TYPE_NS
          record = DNSer::Packet::NS.new(*args)
        when DNSer::Packet::TYPE_CNAME
          record = DNSer::Packet::CNAME.new(*args)
        when DNSer::Packet::TYPE_MX
          record = DNSer::Packet::MX.new(*args)
        when DNSer::Packet::TYPE_TXT
          record = DNSer::Packet::TXT.new(*args)
        when DNSer::Packet::TYPE_AAAA
          record = DNSer::Packet::AAAA.new(*args)
        when DNSer::Packet::TYPE_ANY
          raise(DNSer::Packet::FormatException, "We can't automatically create a response for an 'ANY' request :(")
        else
          raise(DNSer::Packet::FormatException, "We don't know how to answer that type of request!")
        end

        return Answer.new(@name, @type, @cls, ttl, record)
      end

      def ==(other)
        if(!other.is_a?(Question))
          return false
        end

        return (@name == other.name) && (@type == other.type) && (@cls == other.cls)
      end
    end

    # A DNS answer. A DNS response packet contains zero or more Answer records
    # (defined by the 'ancount' value in the header). An answer contains the
    # name of the domain from the question, followed by a resource record.
    class Answer
      attr_reader :name, :type, :cls, :ttl, :rr

      def initialize(name, type, cls, ttl, rr)
        @name = name
        @type = type
        @cls  = cls
        @ttl  = ttl
        @rr   = rr

        if(rr.is_a?(String))
          raise(ArgumentError, "'rr' can't be a string!")
        end
      end

      def ==(other)
        if(!other.is_a?(Answer))
          return false
        end

        # Note: we don't check TTL here, and checking RR probably doesn't work (but we don't actually need it)
        return (@name == other.name) && (@type == other.type) && (@cls == other.cls) && (@rr == other.rr)
      end

      def Answer.parse(data)
        name = data.unpack_name()
        type, cls, ttl, rr_length = data.unpack("nnNn")

        rr = nil
        data.verify_length(rr_length) do
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
        end

        return Answer.new(name, type, cls, ttl, rr)
      end

      def serialize()
        # Hardcoding 0xc00c is kind of ugly, but it always works
        rr = @rr.serialize()
        return [0xc00c, @type, @cls, @ttl, rr.length(), rr].pack("nnnNna*")
      end

      def type_s()
        return DNSer::Packet::TYPES[@type]
      end

      def cls_s()
        return DNSer::Packet::CLSES[@cls]
      end

      def to_s()
        return "#{@name} [#{type_s()} #{cls_s()}]: #{@rr} [TTL = #{@ttl}]"
      end
    end

    def initialize(trn_id, qr, opcode, flags, rcode)
      @trn_id    = trn_id
      @qr        = qr
      @opcode    = opcode
      @flags     = flags
      @rcode     = rcode
      @questions = []
      @answers   = []
    end

    def add_question(question)
      @questions << question
    end

    def add_answer(answer)
      @answers << answer
    end

    def Packet.parse(data)
      data = DnsUnpacker.new(data)
      trn_id, full_flags, qdcount, ancount, _, _ = data.unpack("nnnnnn")

      qr     = (full_flags >> 15) & 0x0001
      opcode = (full_flags >> 11) & 0x000F
      flags  = (full_flags >> 7)  & 0x000F
      rcode  = (full_flags >> 0)  & 0x000F

      packet = Packet.new(trn_id, qr, opcode, flags, rcode)

      0.upto(qdcount - 1) do
        question = Question.parse(data)
        packet.add_question(question)
      end

      0.upto(ancount - 1) do
        answer = Answer.parse(data)
        packet.add_answer(answer)
      end

      return packet
    end

    def get_error(rcode)
      return Packet.new(@trn_id, DNSer::Packet::QR_RESPONSE, DNSer::Packet::OPCODE_QUERY, DNSer::Packet::FLAG_RD | DNSer::Packet::FLAG_RA, rcode)
    end

    def serialize()
      result = ''

      full_flags = ((@qr     << 15) & 0x8000) |
                   ((@opcode << 11) & 0x7800) |
                   ((@flags  <<  7) & 0x0780) |
                   ((@rcode  <<  0) & 0x000F)

      result += [
                  @trn_id,             # trn_id
                  full_flags,          # qr, opcode, flags, rcode
                  @questions.length(), # qdcount
                  @answers.length(),   # ancount
                  0,                   # nscount (ignored)
                  0                    # arcount (ignored)
                ].pack("nnnnnn")

      questions.each do |q|
        result += q.serialize()
      end

      answers.each do |a|
        result += a.serialize()
      end

      return result
    end

    def to_s(brief = false)
      if(brief)
        question = @questions[0] || '<unknown>'

        # Print error packets more clearly
        if(@rcode != DNSer::Packet::RCODE_SUCCESS)
          return "Request for #{question}: error: #{DNSer::Packet::RCODES[@rcode]}"
        end

        if(@qr == DNSer::Packet::QR_QUERY)
          return "Request for #{question}"
        else
          if(@answers.length == 0)
            return "Response for #{question}: n/a"
          else
            return "Response for #{question}: #{@answers[0]} (and #{@answers.length - 1} others)"
          end
        end
      end

      results = ["DNS #{QRS[@qr] || "unknown"}: id=#{@trn_id}, opcode=#{OPCODES[@opcode]}, flags=#{Packet.FLAGS(@flags)}, rcode=#{RCODES[@rcode] || "unknown"}, qdcount=#{@questions.length}, ancount=#{@answers.length}"]

      @questions.each do |q|
        results << "    Question: #{q}"
      end

      @answers.each do |a|
        results << "    Answer: #{a}"
      end

      return results.join("\n")
    end

    def ==(other)
      if(!other.is_a?(Packet))
        return false
      end

      return (@trn_id == other.trn_id) && (@opcode == other.opcode) && (@flags == other.flags) && (@questions == other.questions) && (@answers == other.answers)
    end
  end
end
