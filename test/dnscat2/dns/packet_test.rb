# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dns/packet'

module DNSer
  class PacketTest < ::Test::Unit::TestCase
    def test_create_parse_question()
      packet = Packet.new(
        trn_id: 0x1337,
        qr: QR_QUERY,
        opcode: OPCODE_QUERY,
        flags: FLAG_RD,
        rcode: RCODE_SUCCESS,
      )
      assert_equal(0x1337, packet.trn_id)
      assert_equal(QR_QUERY, packet.qr)
      assert_equal(OPCODE_QUERY, packet.opcode)
      assert_equal(FLAG_RD, packet.flags)
      assert_equal(RCODE_SUCCESS, packet.rcode)

      packet.add_question(
        Question.new(
          name: 'google.com',
          type: TYPE_A,
          cls: CLS_IN,
        )
      )
      assert_equal('google.com', packet.questions[0].name)
      assert_equal(TYPE_A, packet.questions[0].type)
      assert_equal(CLS_IN, packet.questions[0].cls)

      expected = "\x13\x37" + # trn_id
        "\x01\x00" + # Flags
        "\x00\x01" + # qdcount
        "\x00\x00" + # ancount
        "\x00\x00" + # nscount
        "\x00\x00" + # arcount
        "\x06google\x03com\x00" + # name
        "\x00\x01" + # type
        "\x00\x01" # cls
      assert_equal(expected, packet.to_bytes)

      packet = Packet.parse(packet.to_bytes)
      assert_equal(0x1337, packet.trn_id)
      assert_equal(QR_QUERY, packet.qr)
      assert_equal(OPCODE_QUERY, packet.opcode)
      assert_equal(FLAG_RD, packet.flags)
      assert_equal(RCODE_SUCCESS, packet.rcode)
      assert_equal('google.com', packet.questions[0].name)
      assert_equal(TYPE_A, packet.questions[0].type)
      assert_equal(CLS_IN, packet.questions[0].cls)
    end

    def test_create_parse_answer()
      packet = Packet.new(
        trn_id: 0x1337,
        qr: QR_QUERY,
        opcode: OPCODE_QUERY,
        flags: FLAG_RD,
        rcode: RCODE_SUCCESS,
      )
      assert_equal(0x1337, packet.trn_id)
      assert_equal(QR_QUERY, packet.qr)
      assert_equal(OPCODE_QUERY, packet.opcode)
      assert_equal(FLAG_RD, packet.flags)
      assert_equal(RCODE_SUCCESS, packet.rcode)

      packet.add_question(
        Question.new(
          name: 'google.com',
          type: TYPE_A,
          cls: CLS_IN,
        )
      )
      assert_equal('google.com', packet.questions[0].name)
      assert_equal(TYPE_A, packet.questions[0].type)
      assert_equal(CLS_IN, packet.questions[0].cls)

      packet.add_answer(
        Answer.new(
          name: 'google.com',
          type: TYPE_A,
          cls: CLS_IN,
          ttl: 0x12345678,
          rr: A.new(
            address: '1.2.3.4'
          ),
        ),
      )

      packet.add_answer(
        Answer.new(
          name: 'google.com',
          type: TYPE_MX,
          cls: CLS_IN,
          ttl: 0x12345678,
          rr: MX.new(
            name: 'mail.google.com',
            preference: 10,
          ),
        ),
      )
      assert_equal('google.com', packet.answers[0].name)
      assert_equal(TYPE_A, packet.answers[0].type)
      assert_equal(CLS_IN, packet.answers[0].cls)
      assert_equal(0x12345678, packet.answers[0].ttl)
      assert_equal(IPAddr.new('1.2.3.4'), packet.answers[0].rr.address)

      assert_equal('google.com', packet.answers[1].name)
      assert_equal(TYPE_MX, packet.answers[1].type)
      assert_equal(CLS_IN, packet.answers[1].cls)
      assert_equal(0x12345678, packet.answers[1].ttl)
      assert_equal('mail.google.com', packet.answers[1].rr.name)
      assert_equal(10, packet.answers[1].rr.preference)

      expected = "\x13\x37" + # trn_id
        "\x01\x00" + # Flags
        "\x00\x01" + # qdcount
        "\x00\x02" + # ancount
        "\x00\x00" + # nscount
        "\x00\x00" + # arcount

        # Question
        "\x06google\x03com\x00" + # name
        "\x00\x01" + # type
        "\x00\x01" + # cls

        # First answer
        "\xc0\x0c" + # name
        "\x00\x01" + # type
        "\x00\x01" + # cls
        "\x12\x34\x56\x78" + # TTL
        "\x00\x04" + # rr length
        "\x01\x02\x03\x04" + # A rr

        # Second answer
        "\xc0\x0c" + # name
        "\x00\x0f" + # type
        "\x00\x01" + # cls
        "\x12\x34\x56\x78" + # TTL
        "\x00\x09" + # rr length
        "\x00\x0a\x04mail\xc0\x0c" # MX rr (name + preference)

      assert_equal(expected, packet.to_bytes)

      packet = Packet.parse(packet.to_bytes)

      assert_equal(0x1337, packet.trn_id)
      assert_equal(QR_QUERY, packet.qr)
      assert_equal(OPCODE_QUERY, packet.opcode)
      assert_equal(FLAG_RD, packet.flags)
      assert_equal(RCODE_SUCCESS, packet.rcode)
      assert_equal('google.com', packet.questions[0].name)
      assert_equal(TYPE_A, packet.questions[0].type)
      assert_equal(CLS_IN, packet.questions[0].cls)
      assert_equal('google.com', packet.answers[0].name)
      assert_equal(TYPE_A, packet.answers[0].type)
      assert_equal(CLS_IN, packet.answers[0].cls)
      assert_equal(0x12345678, packet.answers[0].ttl)
      assert_equal(IPAddr.new('1.2.3.4'), packet.answers[0].rr.address)
      assert_equal('google.com', packet.answers[1].name)
      assert_equal(TYPE_MX, packet.answers[1].type)
      assert_equal(CLS_IN, packet.answers[1].cls)
      assert_equal(0x12345678, packet.answers[1].ttl)
      assert_equal('mail.google.com', packet.answers[1].rr.name)
      assert_equal(10, packet.answers[1].rr.preference)
    end
  end
end
