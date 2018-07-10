# Encoding: ASCII-8BIT
##
# name_helper.rb
# Created July, 2018
# By Ron Bowes
#
# See: LICENSE.md
##

require 'nesser'
require 'singlogger'
require 'thread'

require 'dnscat2/core/dnscat_exception'

require 'dnscat2/core/tunnel_drivers/dns/driver_dns_constants'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class NameHelper
          ##
          # tag: The text that goes in front of the name
          # domain: The text that goes after the name
          # max_subdomain_length: The maximum length of a sub-domain name (like
          #  the 'www' of 'www.google.com') - 63 is a safe bet
          # max_subdomain_jitter: The amount that could be subtracted from
          #  max_subdomain_length at random - subdomains of 15 bytes =~ the same
          #  amount of data as 63 bytes, so 42 is a pretty safe jitter that
          #  doesn't compromise too much on bandwidth
          public
          def initialize(tag:, domain:, max_subdomain_length: 63, max_subdomain_jitter: 42)
            @l = SingLogger.instance()
            @tag = tag
            @domain = domain

            if(max_subdomain_length < 1 || max_subdomain_length > 63)
              raise(DnscatException, "max_subdomain_length is not sane")
            end
            @max_subdomain_length = max_subdomain_length

            if(max_subdomain_jitter < 0 || max_subdomain_length - max_subdomain_jitter < 0)
              raise(DnscatException, "max_subdomain_jitter is not sane")
            end
            @max_subdomain_jitter = max_subdomain_jitter
          end

          private
          def _find_max(sub_length:, available:)
            # The math behind this is:
            # total_length = sub_length * n + (n - 1)
            # length must be < = available
            #
            # TODO: This is an ugly bruteforce solution - find some pretty math
            # that matches
            256.step(1, -1) do |i|
              total_length = (sub_length * i) + (i - 1)

              if(total_length <= MAX_RR_LENGTH)
                return i
              end
            end

            raise(DnscatException, "Couldn't find a work-able length for DNS parameters")
          end

          private
          def _number_of_periods(sub_length:, available:, extra:)
            if(extra.nil?)
              # If there's no extra, we have one "extra" space, because no
              # period before the "first" subdomain
              return (available + 1) / (sub_length + 1)
            else
              # If there's an extra, we need to subtract it from the available
              # bytes, as well as its period
              return ((available - extra.length - 1) / (sub_length + 1))
            end
            # We add 1 to each sub_length to account for its period
          end

          ##
          # The maximum length of data that can be encoded, including pre- or
          # appending tags and domain names.
          ##
          public
          def max_length()
            max_total_length = MAX_RR_LENGTH
            if(@tag)
              max_total_length = max_total_length - @tag.length
            end
            if(@domain)
              max_total_length = max_total_length - @domain.length
            end

            number_of_periods = _number_of_periods(sub_length: @max_subdomain_length - @max_subdomain_jitter, available: MAX_RR_LENGTH, extra: @tag || @domain)
            number_of_periods_2 = _find_max(sub_length: @max_subdomain_length - @max_subdomain_jitter, available: max_total_length)


            return (max_total_length - number_of_periods) / 2, number_of_periods, number_of_periods_2
          end

          ##
          # Gets a string of data, no longer than max_length().
          #
          # Returns a resource record of the correct type.
          ##
          public
          def encode_name(data:)
            @l.debug("TunnelDrivers::DNS::NameHelper Encoding #{data.length} bytes of data")

            name = []
            data = data.unpack('H*').pop()
            while(data && data.length >= @max_subdomain_length)
              length = ::Kernel::rand((@max_subdomain_length - @max_subdomain_jitter)..@max_subdomain_length)
              sub, data = data[0..(length - 1)], data[length..-1]
              name << sub
            end
            # Add the last of the data
            name << data

            name = name.join('.')
            puts(name)

            # Add the @tag or @domain
            if(@tag)
              name = "#{@tag}.#{name}"
            end
            if(@domain)
              name = "#{name}.#{@domain}"
            end

            # Always double check that we aren't too big for a DNS packet
            if(name.length > MAX_RR_LENGTH)
              raise(DnscatException, "Tried to encode a name that's too long for the protocol (#{name.length} bytes)")
            end

            return name
          end
        end
      end
    end
  end
end
