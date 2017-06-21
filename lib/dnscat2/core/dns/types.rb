# Encoding: ASCII-8BIT
##
# types.rb
# Created June 20, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

require 'ipaddr'

require 'dnscat2/core/dns/constants'
require 'dnscat2/core/dns/dns_exception'
require 'dnscat2/core/dns/packer'
require 'dnscat2/core/dns/unpacker'

module DNSer
  class A
    attr_accessor :address

    def initialize(address:)
      if !address.is_a?(String)
        raise(FormatException, "String required!")
      end

      begin
        @address = IPAddr.new(address)
      rescue IPAddr::InvalidAddressError => e
        raise(FormatException, "Invalid address: %s" % e)
      end

      if !@address.ipv4?()
        raise(FormatException, "IPv4 address required!")
      end
    end

    def self.parse(unpacker)
      data = unpacker.unpack('AAAA').join()
      return A.new(address: IPAddr.ntop(data))
    end

    def pack(packer)
      packer.pack('CCCC', *@address.hton().bytes())
    end

    def to_s()
      return "#{@address} [A]"
    end
  end

  class NS
    attr_accessor :name

    def initialize(name:)
      @name = name
    end

    def self.parse(unpacker)
      return self.new(name: unpacker.unpack_name())
    end

    def pack(packer)
      packer.pack_name(@name)
    end

    def to_s()
      return "#{@name} [NS]"
    end
  end

  class CNAME
    attr_accessor :name

    def initialize(name:)
      @name = name
    end

    def self.parse(unpacker)
      return self.new(name: unpacker.unpack_name())
    end

    def pack(packer)
      packer.pack_name(@name)
    end

    def to_s()
      return "#{@name} [CNAME]"
    end
  end

  class SOA
    attr_accessor :primary, :responsible, :serial, :refresh, :retry_interval, :expire, :ttl

    def initialize(primary:, responsible:, serial:, refresh:, retry_interval:, expire:, ttl:)
      @primary = primary
      @responsible = responsible
      @serial = serial
      @refresh = refresh
      @retry_interval = retry_interval
      @expire = expire
      @ttl = ttl
    end

    def self.parse(unpacker)
      primary = unpacker.unpack_name()
      responsible = unpacker.unpack_name()
      serial, refresh, retry_interval, expire, ttl = unpacker.unpack("NNNNN")

      return SOA.new(primary: primary, responsible: responsible, serial: serial, refresh: refresh, retry_interval: retry_interval, expire: expire, ttl: ttl)
    end

    def pack(packer)
      packer.pack_name(@primary)
      packer.pack_name(@responsible)
      packer.pack("NNNNN", @serial, @refresh, @retry_interval, @expire, @ttl)
    end

    def to_s()
      return "Primary name server = %s, responsible authority's mailbox: %s, serial number: 0x%08x, refresh interval: 0x%08x, retry interval: 0x%08x, expire limit: 0x%08x, min_ttl: 0x%08x, [SOA]" % [
        @primary,
        @responsible,
        @serial,
        @refresh,
        @retry_interval,
        @expire,
        @ttl,
      ]
    end
  end

#  class MX
#    attr_accessor :preference, :name
#
#    def initialize(name, preference = 10)
#      if(!name.is_a?(String) || !preference.is_a?(Fixnum))
#        raise ArgumentError("Creating an MX record wrong! Please file a bug!")
#      end
#      @name = name
#      @preference = preference
#    end
#
#    def self.parse(data)
#      preference = data.unpack("n").pop()
#      name = data.unpack_name()
#
#      return MX.new(name, preference)
#    end
#
#    def pack(packer)
#      packer.pack_name(name)
#      name = DNSer::Packet::DnsUnpacker.pack_name(@name)
#      return [@preference, name].pack("na*")
#    end
#
#    def to_s()
#      return "#{@preference} #{@name} [MX]"
#    end
#  end
#
#  class TXT
#    attr_accessor :data
#
#    def initialize(data)
#      @data = data
#    end
#
#    def self.parse(data)
#      len = data.unpack("C").pop()
#      bytes = data.unpack("A#{len}").pop()
#
#      return TXT.new(bytes)
#    end
#
#    def to_bytes()
#      return [@data.length, data].pack("Ca*")
#    end
#
#    def to_s()
#      return "#{@data} [TXT]"
#    end
#  end
#
#  class AAAA
#    attr_accessor :address
#
#    def initialize(address)
#      @address = IPAddr.new(address)
#
#      if(!@address.ipv6?())
#        raise(FormatException, "IPv6 address required!")
#      end
#    end
#
#    def self.parse(data)
#      address = data.unpack("A16").pop()
#      return AAAA.new(IPAddr.ntop(address))
#    end
#
#    def to_bytes()
#      return @address.hton()
#    end
#
#    def to_s()
#      return "#{@address} [A]"
#    end
#  end
#
#  class RRUnknown
#    def initialize(type, data)
#      @type = type
#      @data = data
#    end
#
#    def self.parse(type, data, length)
#      data = data.unpack("A#{length}").pop()
#      return RRUnknown.new(type, data)
#    end
#
#    def to_bytes()
#      return @data
#    end
#
#    def to_s()
#      return "(Unknown record type #{@type}): #{@data.unpack("H*")}"
#    end
#  end
end