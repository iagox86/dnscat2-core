require 'test_helper'

require 'dnscat2/core/libs/hex'

class Dnscat2::Core::HexTestToS < Test::Unit::TestCase
  def test_empty_string()
    str = Dnscat2::Core::Libs::Hex.to_s('')
    assert_equal(str, '')
  end

  def test_one_character_string()
    str = Dnscat2::Core::Libs::Hex.to_s('A')
    assert_equal(str, '00000000  41                                                A')
  end

  def test_sixteen_character_string()
    str = Dnscat2::Core::Libs::Hex.to_s('AAAAAAAAAAAAAAAA')
    assert_equal(str, '00000000  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA')
  end

  def test_more_than_sixteen()
    str = Dnscat2::Core::Libs::Hex.to_s('AAAAAAAAAAAAAAAAAAAA')
    assert_equal(str, "00000000  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA\n" +
                      "00000010  41 41 41 41                                       AAAA")
  end

  def test_null_bytes()
    str = Dnscat2::Core::Libs::Hex.to_s("A\0A\0A")
    assert_equal(str, '00000000  41 00 41 00 41                                    A.A.A')
  end

  def test_newlines()
    str = Dnscat2::Core::Libs::Hex.to_s("A\nA\nA")
    assert_equal(str, '00000000  41 0a 41 0a 41                                    A.A.A')
  end

  def test_exactly_thirty_two()
    str = Dnscat2::Core::Libs::Hex.to_s('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    assert_equal(str, "00000000  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA\n" +
                      "00000010  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA")
  end

  def test_indent()
    str = Dnscat2::Core::Libs::Hex.to_s('A', indent: 1)
    assert_equal(str, ' 00000000  41                                                A')
  end

  def test_indent_two_lines()
    str = Dnscat2::Core::Libs::Hex.to_s('AAAAAAAAAAAAAAAAAAAA', indent: 2)
    assert_equal(str, "  00000000  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA\n" +
                      "  00000010  41 41 41 41                                       AAAA")
  end

  def test_indent_with_sixteen_characters()
    str = Dnscat2::Core::Libs::Hex.to_s('AAAAAAAAAAAAAAAA', indent: 2)
    assert_equal(str, '  00000000  41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41   AAAAAAAAAAAAAAAA')
  end
end
