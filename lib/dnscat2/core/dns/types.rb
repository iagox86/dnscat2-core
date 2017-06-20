# Encoding: ASCII-8BIT
##
# types.rb
# Created June 20, 2017
# By Ron Bowes
#
# See: LICENSE.md
##

module DNSer
  class A
    attr_accessor :address

    def initialize(address)
      @address = IPAddr.new(address)

      if(!@address.ipv4?())
        raise(FormatException, "IPv4 address required!")
      end
    end

    def A.parse(data)
      address = data.unpack("A4").pop()
      return A.new(IPAddr.ntop(address))
    end

    def serialize()
      return @address.hton()
    end

    def to_s()
      return "#{@address} [A]"
    end
  end

  class NS
    attr_accessor :name

    def initialize(name)
      @name = name
    end

    def NS.parse(data)
      return NS.new(data.unpack_name())
    end

    def serialize()
      return DNSer::Packet::DnsUnpacker.pack_name(@name)
    end

    def to_s()
      return "#{@name} [NS]"
    end
  end

  class CNAME
    attr_accessor :name

    def initialize(name)
      @name = name
    end

    def CNAME.parse(data)
      return CNAME.new(data.unpack_name())
    end

    def serialize()
      return DNSer::Packet::DnsUnpacker.pack_name(@name)
    end

    def to_s()
      return "#{@name} [CNAME]"
    end
  end

  class SOA
    attr_accessor :primary, :responsible, :serial, :refresh, :retry_interval, :expire, :ttl

    def initialize(primary, responsible, serial, refresh, retry_interval, expire, ttl)
      @primary = primary
      @responsible = responsible
      @serial = serial
      @refresh = refresh
      @retry_interval = retry_interval
      @expire = expire
      @ttl = ttl
    end

    def SOA.parse(data)
      primary = data.unpack_name()
      responsible = data.unpack_name()
      serial, refresh, retry_interval, expire, ttl = data.unpack("NNNNN")

      return SOA.new(primary, responsible, serial, refresh, retry_interval, expire, ttl)
    end

    def serialize()
      return [
        DNSer::Packet::DnsUnpacker.pack_name(@primary),
        DNSer::Packet::DnsUnpacker.pack_name(@responsible),
        @serial,
        @refresh,
        @retry_interval,
        @expire,
        @ttl
      ].pack("a*a*NNNNN")
    end

    def to_s()
      return "Primary name server = #{@primary}, responsible authority's mailbox: #{@responsible}, serial number: #{@serial}, refresh interval: #{@refresh}, retry interval: #{@retry_interval}, expire limit: #{@expire}, min_ttl: #{@ttl} [SOA]"
    end
  end

  class MX
    attr_accessor :preference, :name

    def initialize(name, preference = 10)
      if(!name.is_a?(String) || !preference.is_a?(Fixnum))
        raise ArgumentError("Creating an MX record wrong! Please file a bug!")
      end
      @name = name
      @preference = preference
    end

    def MX.parse(data)
      preference = data.unpack("n").pop()
      name = data.unpack_name()

      return MX.new(name, preference)
    end

    def serialize()
      name = DNSer::Packet::DnsUnpacker.pack_name(@name)
      return [@preference, name].pack("na*")
    end

    def to_s()
      return "#{@preference} #{@name} [MX]"
    end
  end

  class TXT
    attr_accessor :data

    def initialize(data)
      @data = data
    end

    def TXT.parse(data)
      len = data.unpack("C").pop()
      bytes = data.unpack("A#{len}").pop()

      return TXT.new(bytes)
    end

    def serialize()
      return [@data.length, data].pack("Ca*")
    end

    def to_s()
      return "#{@data} [TXT]"
    end
  end

  class AAAA
    attr_accessor :address

    def initialize(address)
      @address = IPAddr.new(address)

      if(!@address.ipv6?())
        raise(FormatException, "IPv6 address required!")
      end
    end

    def AAAA.parse(data)
      address = data.unpack("A16").pop()
      return AAAA.new(IPAddr.ntop(address))
    end

    def serialize()
      return @address.hton()
    end

    def to_s()
      return "#{@address} [A]"
    end
  end

  class RRUnknown
    def initialize(type, data)
      @type = type
      @data = data
    end

    def RRUnknown.parse(type, data, length)
      data = data.unpack("A#{length}").pop()
      return RRUnknown.new(type, data)
    end

    def serialize()
      return @data
    end

    def to_s()
      return "(Unknown record type #{@type}): #{@data.unpack("H*")}"
    end
  end
end
