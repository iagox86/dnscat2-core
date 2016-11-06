require 'test_helper'

require 'dnscat2/core/libs/crypto_helper'

class Dnscat2::Core::CryptoHelperTest_BignumToBinary < Test::Unit::TestCase
  def test_fixnum()
    result = Dnscat2::Core::Libs::CryptoHelper.bignum_to_binary(0x1122)
    assert_equal("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x11\x22".force_encoding('ASCII-8BIT'), result)
  end

  def test_bignum()
    result = Dnscat2::Core::Libs::CryptoHelper.bignum_to_binary(0x11223344556677889900aabbccddeeff)
    assert_equal("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x11\x22\x33\x44\x55\x66\x77\x88\x99\0\xaa\xbb\xcc\xdd\xee\xff".force_encoding('ASCII-8BIT'), result)
  end

  def test_16_byte()
    result = Dnscat2::Core::Libs::CryptoHelper.bignum_to_binary(0x11223344, size: 16)
    assert_equal("\0\0\0\0\0\0\0\0\0\0\0\0\x11\x22\x33\x44".force_encoding('ASCII-8BIT'), result)
  end

  def test_64_byte()
    result = Dnscat2::Core::Libs::CryptoHelper.bignum_to_binary(0x11223344, size: 64)
    assert_equal("\0"*60 + "\x11\x22\x33\x44".force_encoding('ASCII-8BIT'), result)
  end

  def test_not_bignum()
    assert_raise(ArgumentError) do
      Dnscat2::Core::Libs::CryptoHelper.bignum_to_binary('hi')
    end
  end
end

class Dnscat2::Core::CryptoHelperTest_BignumToText < Test::Unit::TestCase
  def test_fixnum()
    result = Dnscat2::Core::Libs::CryptoHelper.bignum_to_text(0x1122)
    assert_equal("0000000000000000000000000000000000000000000000000000000000001122".force_encoding('ASCII-8BIT'), result)
  end

  def test_bignum()
    result = Dnscat2::Core::Libs::CryptoHelper.bignum_to_text(0x11223344556677889900aabbccddeeff)
    assert_equal("0000000000000000000000000000000011223344556677889900aabbccddeeff".force_encoding('ASCII-8BIT'), result)
  end

  def test_16_byte()
    result = Dnscat2::Core::Libs::CryptoHelper.bignum_to_text(0x11223344, size: 16)
    assert_equal("00000000000000000000000011223344".force_encoding('ASCII-8BIT'), result)
  end

  def test_64_byte()
    result = Dnscat2::Core::Libs::CryptoHelper.bignum_to_text(0x11223344, size: 64)
    assert_equal("00"*60 + "11223344".force_encoding('ASCII-8BIT'), result)
  end

  def test_not_bignum()
    assert_raise(ArgumentError) do
      Dnscat2::Core::Libs::CryptoHelper.bignum_to_text('hi')
    end
  end
end

class Dnscat2::Core::CryptoHelperTest_BinaryToBignum < Test::Unit::TestCase
  def test_normal()
    result = Dnscat2::Core::Libs::CryptoHelper.binary_to_bignum("\x11\x22")
    assert_equal(0x1122, result)
  end

  def test_not_string()
    assert_raises(ArgumentError) do
      Dnscat2::Core::Libs::CryptoHelper.binary_to_bignum(123)
    end
  end
end
