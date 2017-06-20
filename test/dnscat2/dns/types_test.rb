# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dns/types'

module DNSer
  class ATest < ::Test::Unit::TestCase
    def test_a()
      # Create
      record = A.new(address: '1.2.3.4')
      assert_equal(IPAddr.new('1.2.3.4'), record.address)

      # Serialize
      assert_equal("\x01\x02\x03\x04", record.to_bytes())

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
end
