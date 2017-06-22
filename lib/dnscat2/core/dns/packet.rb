# Encoding: ASCII-8BIT
##
# packet.rb
# Created June 20, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

require 'dnscat2/core/dns/answer'
require 'dnscat2/core/dns/constants'
require 'dnscat2/core/dns/dns_exception'
require 'dnscat2/core/dns/packer'
require 'dnscat2/core/dns/question'
require 'dnscat2/core/dns/rr_types'
require 'dnscat2/core/dns/unpacker'

module DNSer
  class Packet
    attr_accessor :trn_id, :qr, :opcode, :flags, :rcode, :questions, :answers

    def initialize(trn_id:, qr:, opcode:, flags:, rcode:, questions:[], answers:[])
      @trn_id    = trn_id
      @qr        = qr
      @opcode    = opcode
      @flags     = flags
      @rcode     = rcode

      questions.each { |q| raise(DnsException, "Questions must be of type Answer!") if !q.is_a?(Question) }
      @questions = questions

      answers.each { |a| raise(DnsException, "Answers must be of type Answer!") if !a.is_a?(Answer) }
      @answers   = answers
    end

    def add_question(question)
      if !question.is_a?(Question)
        raise(DnsException, "Questions must be of type Question!")
      end

      @questions << question
    end

    def add_answer(answer)
      if !answer.is_a?(Answer)
        raise(DnsException, "Questions must be of type Question!")
      end

      @answers << answer
    end

    def self.parse(data)
      unpacker = Unpacker.new(data)
      trn_id, full_flags, qdcount, ancount, _, _ = unpacker.unpack("nnnnnn")

      qr     = (full_flags >> 15) & 0x0001
      opcode = (full_flags >> 11) & 0x000F
      flags  = (full_flags >> 7)  & 0x000F
      rcode  = (full_flags >> 0)  & 0x000F

      packet = self.new(
        trn_id: trn_id,
        qr: qr,
        opcode: opcode,
        flags: flags,
        rcode: rcode,
        questions: [],
        answers: [],
      )

      0.upto(qdcount - 1) do
        question = Question.unpack(unpacker)
        packet.add_question(question)
      end

      0.upto(ancount - 1) do
        answer = Answer.unpack(unpacker)
        packet.add_answer(answer)
      end

      return packet
    end

    def answer(question: nil, answers:[])
      question = question || @questions[0]

      return Packet.new(
        trn_id: @trn_id,
        qr: QR_RESPONSE,
        opcode: OPCODE_QUERY,
        flags: FLAG_RD | FLAG_RA,
        rcode: RCODE_SUCCESS,
        questions: [question],
        answers: answers,
      )
    end

    def error(rcode:)
      return Packet.new(
        trn_id: @trn_id,
        qr: QR_RESPONSE,
        opcode: OPCODE_QUERY,
        flags: FLAG_RD | FLAG_RA,
        rcode: rcode,
        questions: [],
        answers: [],
      )
    end

    def to_bytes()
      packer = Packer.new()

      full_flags = ((@qr     << 15) & 0x8000) |
                   ((@opcode << 11) & 0x7800) |
                   ((@flags  <<  7) & 0x0780) |
                   ((@rcode  <<  0) & 0x000F)

      packer.pack('nnnnnn',
        @trn_id,             # trn_id
        full_flags,          # qr, opcode, flags, rcode
        @questions.length(), # qdcount
        @answers.length(),   # ancount
        0,                   # nscount (we don't handle)
        0,                   # arcount (we don't handle)
      )

      questions.each do |q|
        q.pack(packer)
      end

      answers.each do |a|
        a.pack(packer)
      end

      return packer.get()
    end

    def to_s(brief = false)
      if(brief)
        question = @questions[0] || '<unknown>'

        # Print error packets more clearly
        if(@rcode != RCODE_SUCCESS)
          return "Request for #{question}: error: #{RCODES[@rcode]}"
        end

        if(@qr == QR_QUERY)
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
  end
end
