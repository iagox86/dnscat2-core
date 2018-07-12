# Encoding: ASCII-8BIT
require 'test_helper'

require 'dnscat2/core/dnscat_exception'
require 'dnscat2/core/tunnel_drivers/encoders/base32'
require 'dnscat2/core/tunnel_drivers/encoders/hex'

require 'dnscat2/core/tunnel_drivers/dns/mx_handler'

module Dnscat2
  module Core
    module TunnelDrivers
      module DNS
        class NameHelperTest < ::Test::Unit::TestCase
          def test_mx_normal()
            handler = MXHandler.new(
              tag: nil,
              domain: nil,
              max_subdomain_length: 63,
              encoder: Encoders::Hex,
            )

            rr = handler.encode(data: 'AAAA')

            assert_equal('41414141', rr.name)
          end

          def test_mx_with_tag()
            handler = MXHandler.new(
              tag: 'aaa',
              domain: nil,
              max_subdomain_length: 63,
              encoder: Encoders::Hex,
            )

            rr = handler.encode(data: 'AAAA')

            assert_equal('aaa.41414141', rr.name)
          end

          def test_mx_with_domain()
            handler = MXHandler.new(
              tag: nil,
              domain: 'aaa',
              max_subdomain_length: 63,
              encoder: Encoders::Hex,
            )

            rr = handler.encode(data: 'AAAA')

            assert_equal('41414141.aaa', rr.name)
          end

          def test_mx_with_different_subdomain_length()
            handler = MXHandler.new(
              tag: nil,
              domain: nil,
              max_subdomain_length: 3,
              encoder: Encoders::Hex,
            )

            rr = handler.encode(data: 'AAAA')

            assert_equal('414.141.41', rr.name)
          end

          def test_mx_with_different_encoder()
            handler = MXHandler.new(
              tag: nil,
              domain: nil,
              max_subdomain_length: 63,
              encoder: Encoders::Base32,
            )

            rr = handler.encode(data: 'AAAA')

            assert_equal('ifaucqi', rr.name)
          end

          def test_mx_with_just_less_than_too_much_data()
            handler = MXHandler.new(
              tag: nil,
              domain: nil,
              max_subdomain_length: 63,
              encoder: Encoders::Hex,
            )

            rr = handler.encode(data: 'A' * handler.max_length())
            assert_not_nil(rr)
            assert_not_nil(rr.name)
          end

          def test_mx_with_too_much_data()
            handler = MXHandler.new(
              tag: nil,
              domain: nil,
              max_subdomain_length: 63,
              encoder: Encoders::Hex,
            )

            assert_raises(DnscatException) do
              handler.encode(data: 'A' * (handler.max_length() + 1))
            end
          end

          def test_mx_with_just_less_than_too_much_data_and_a_domain()
            handler = MXHandler.new(
              tag: nil,
              domain: 'aaaaaaaaaaaaaaaaa',
              max_subdomain_length: 10,
              encoder: Encoders::Hex,
            )

            rr = handler.encode(data: 'A' * handler.max_length())
            assert_not_nil(rr)
            assert_not_nil(rr.name)
          end

          def test_mx_with_too_much_data_and_a_domain()
            handler = MXHandler.new(
              tag: nil,
              domain: 'aaaaaaaaaaaaaaaaa',
              max_subdomain_length: 10,
              encoder: Encoders::Hex,
            )

            assert_raises(DnscatException) do
              handler.encode(data: 'A' * (handler.max_length() + 1))
            end
          end
        end
      end
    end
  end
end
