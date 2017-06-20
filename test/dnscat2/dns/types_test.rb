# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dns/types'

module DNSer
  class A_Test < ::Test::Unit::TestCase
    def test_a()
      # Create
      record = A.new(address: '1.2.3.4')
      assert_equal(IPAddr.new('1.2.3.4'), record.address)

      # Stringify
      assert_equal('1.2.3.4 [A]', record.to_s)

      # Pack
      packer = Packer.new()
      record.pack(packer)
      assert_equal("\x01\x02\x03\x04", packer.get())
    end

    def test_parse_a()
      data = Unpacker.new("ABCD")
      record = A.parse(data)
      assert_equal(IPAddr.new('65.66.67.68'), record.address)
    end

    def test_invalid_a()
      assert_raises(FormatException) do
        A.new(address: 123)
      end
      assert_raises(FormatException) do
        A.new(address: '::1')
      end
      assert_raises(FormatException) do
        A.new(address: '500.hi')
      end
    end
  end

  class NS_Test < ::Test::Unit::TestCase
    def test_ns()
      # Create
      record = NS.new(name: 'test.com')
      assert_equal('test.com', record.name)

      # Stringify
      assert_equal('test.com [NS]', record.to_s)

      # Pack
      packer = Packer.new()
      record.pack(packer)
      assert_equal("\x04test\x03com\x00", packer.get())
    end

    def test_parse_ns()
      data = Unpacker.new("\x04test\x03com\x00")
      record = NS.parse(data)
      assert_equal('test.com', record.name)
    end
  end
end
