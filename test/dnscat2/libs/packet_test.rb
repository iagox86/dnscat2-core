require 'test_helper'

require 'dnscat2/core/libs/packet'

class Dnscat2::Core::CreateSynTest < Test::Unit::TestCase
  def test_create_syn()
    syn = Dnscat2::Core::Libs::SynPacketNg.new(0x3344, 0x5566, {
      :packet_id => 0x1122,
    })
    bytes = syn.to_bytes()
    assert_equal("\x11\x22\x00\x33\x44\x55\x66\x00\x00", bytes)
  end

  def test_with_name()
    syn = Dnscat2::Core::Libs::SynPacketNg.new(0x3344, 0x5566, {
      :packet_id => 0x1122,
      :name => 'name',
    })
    bytes = syn.to_bytes()
    assert_equal("\x11\x22\x00\x33\x44\x55\x66\x00\x01name\x00", bytes)
  end

  def test_with_zero_length_name()
    syn = Dnscat2::Core::Libs::SynPacketNg.new(0x3344, 0x5566, {
      :packet_id => 0x1122,
      :name => '',
    })
    bytes = syn.to_bytes()
    assert_equal("\x11\x22\x00\x33\x44\x55\x66\x00\x01\x00", bytes)
  end
end

class Dnscat2::Core::ParseSynTest < Test::Unit::TestCase
  def test_header_too_short()
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse('')
    end
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse('A')
    end
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse('AA')
    end
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse('AAA')
    end
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse('AAAA')
    end
  end

  def test_body_too_short()
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse("AA\x00AA")
    end
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse("AA\x00AAA")
    end
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse("AA\x00AAAA")
    end
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse("AA\x00AAAAA")
    end
  end

  def test_no_name()
    syn = Dnscat2::Core::Libs::SynPacketNg.parse("\x11\x22\x00\x33\x44\x55\x66\x00\x00")
    assert_equal(0x1122, syn.packet_id)
    assert_equal(0x3344, syn.session_id)
    assert_equal(0x5566, syn.isn)
    assert_equal(nil, syn.name)
  end

  def test_with_name()
    syn = Dnscat2::Core::Libs::SynPacketNg.parse("\x11\x22\x00\x33\x44\x55\x66\x00\x01name\x00")
    assert_equal(0x1122, syn.packet_id)
    assert_equal(0x3344, syn.session_id)
    assert_equal(0x5566, syn.isn)
    assert_equal('name', syn.name)
  end

  def test_with_no_null_termination_on_name()
    assert_raises(Dnscat2::Core::Libs::DnscatException) do
      Dnscat2::Core::Libs::SynPacketNg.parse("\x11\x22\x00\x33\x44\x55\x66\x00\x01name")
    end
  end

  def test_wrong_packet_type()
    assert_raises(ArgumentError) do
      Dnscat2::Core::Libs::SynPacketNg.parse("\x11\x22\x01\x33\x44\x55\x66\x00\x00")
    end
  end
end
