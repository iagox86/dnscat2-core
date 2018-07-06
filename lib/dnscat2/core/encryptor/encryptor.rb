##
# encryptor.rb
# Created October, 2015
# By Ron Bowes
#
# See: LICENSE.md
#
# This class implements the core of the dnscat2 encryption!
#
# To use this class, create a new instance with a pre-shared secret (if there's
# no shared secret, a random string is fine - just long as it's reasonably
# unguessable.
#
# Then, when the client sends their public keys, call
# `encryptor.set_their_public_key()` with their public key x and y values as
# integers. This causes a new private key to be generated, and returns the
# associated public keys that can be sent to the client.
#
# After that, it's possible to optionally call `set_their_authenticator`() with
# the client's authenticator, which verifies that they have the same pre-shared
# secret. It's possible to continue without doing this, but most privacy
# guarantees are lost against an active attacker.
#
# Alternatively, the user can manually authenticate a connection using a short
# authentication string, which is a set of 6 English words from a set of 256,
# which adds 56 bits of entropy that an attacker would have to break in real-
# time. Once that's done, `authenticate!()` can be called to mark the
# connection as manually authenticated.
#
# TODO: Disallow unauthenticated connections from sending or receiving data
#
# Once the connection is authenticated (or not), then the function
# `decrypt_and_encrypt()` will attempt to decrypt the data passed to it.
# The data is a full (header + body) dnscat2 encrypted packet. The packet has
# been encrypted and signed. The signature is verified, the nonce is verified
# not to be an old value, and the packet is decrypted.
#
# The decrypted packet is passed to `decrypt_encrypt_data()`'s block. Whatever
# the block returns is then encrypted and returned from the function. It can
# then be put "on the wire".
#
# When one of the nonce values gets too high, the connection needs to be
# renegotiated. If we overflow nonce values past 0xFFFF, it will begin to fail
# at decrypting anything.
#
# This renegotiation must be initiated by the client, and is as simple as
# sending a new public key (re-using the same public key causes an error) and
# passing that public key into `set_their_public_key()`.
#
# Until `decrypt_and_encrypt()` returns, both keys can simultaneously be used.
# that allows some overlap between keys. As soon as the new key is successfully
# used, the old key is wiped out.
##

require 'ecdsa'
require 'salsa20'
require 'securerandom'
require 'singlogger'
require 'sha3'

require 'dnscat2/core/dnscat_exception'
require 'dnscat2/core/encryptor/sas'
require 'dnscat2/core/libs/crypto_helper'

module Dnscat2
  module Core
    module Encryptor
      class Error < DnscatException
      end

      class Encryptor
        # Only make keys accessible when we're doing unit tests
        if TESTING
          attr_accessor :keys
        end

        ECDH_GROUP = ECDSA::Group::Nistp256

        def initialize(preshared_secret:)
          @l = SingLogger.instance()

          @l.debug("Encryptor: New instance! PSK = `#{preshared_secret}`")

          @preshared_secret = preshared_secret

          # Start off as unauthenticated
          @authenticated = false

          # Start with encryption turned off
          @keys = {
            # TODO: When is my_nonce actually changed?
            :my_nonce            => -1,
            :their_nonce         => -1,
            :my_private_key      => nil,
            :my_public_key       => nil,
            :their_public_key    => nil,
            :shared_secret       => nil,
            :their_authenticator => nil,
            :my_authenticator    => nil,
            :their_write_key     => nil,
            :their_mac_key       => nil,
            :my_write_key        => nil,
            :my_mac_key          => nil,
          }
          @old_keys = nil
        end

        def _ensure_shared_secret!()
          if @keys[:shared_secret].nil?
            raise(Error, "State problem with the encryptor: trying to take an action while shared_secret isn't set")
          end
        end

        def _create_key(key_name)
          @l.debug("Encryptor: creating new key: #{key_name}")

          _ensure_shared_secret!()

          return SHA3::Digest::SHA256.digest(Libs::CryptoHelper.bignum_to_binary(@keys[:shared_secret]) + key_name)
        end

        def _create_authenticator(name, preshared_secret)
          @l.debug("Encryptor: creating authenticator: #{name}")

          _ensure_shared_secret!()

          return SHA3::Digest::SHA256.digest(name +
            Libs::CryptoHelper.bignum_to_binary(@keys[:shared_secret]) +
            Libs::CryptoHelper.bignum_to_binary(@keys[:their_public_key].x) +
            Libs::CryptoHelper.bignum_to_binary(@keys[:their_public_key].y) +
            Libs::CryptoHelper.bignum_to_binary(@keys[:my_public_key].x) +
            Libs::CryptoHelper.bignum_to_binary(@keys[:my_public_key].y) +
            preshared_secret
          )
        end

        def sas()
          _ensure_shared_secret!()

          return SAS.get_sas(
            Libs::CryptoHelper.bignum_to_binary(@keys[:shared_secret]) +
            Libs::CryptoHelper.bignum_to_binary(@keys[:their_public_key].x) +
            Libs::CryptoHelper.bignum_to_binary(@keys[:their_public_key].y) +
            Libs::CryptoHelper.bignum_to_binary(@keys[:my_public_key].x) +
            Libs::CryptoHelper.bignum_to_binary(@keys[:my_public_key].y)
          )
        end

        # Returns true if something was changed
        def set_their_public_key!(their_public_key_x, their_public_key_y, testing_my_private_key:nil)
          # Check if we're actually changing anything
          if(@keys[:their_public_key_x] == their_public_key_x && @keys[:their_public_key_y] == their_public_key_y)
            raise(Error, "Attempted to cycle to the same key!")
          end

          # We keep a copy of the previous key so we can decrypt any stragglers
          if(@keys[:shared_secret])
            @old_keys = @keys
          end

          # The first nonce should be 0
          @keys = {
            :my_nonce => -1,
            :their_nonce => -1,
          }

          if TESTING
            @l.error("Encryptor: Setting a fake testing key!")
            @keys[:my_private_key]      = testing_my_private_key || (1 + SecureRandom.random_number(ECDH_GROUP.order - 1))
          else
            @keys[:my_private_key]      = (1 + SecureRandom.random_number(ECDH_GROUP.order - 1))
          end
          @keys[:my_public_key]       = ECDH_GROUP.generator.multiply_by_scalar(@keys[:my_private_key])
          @keys[:their_public_key_x]  = their_public_key_x
          @keys[:their_public_key_y]  = their_public_key_y
          @keys[:their_public_key]    = ECDSA::Point.new(ECDH_GROUP, their_public_key_x, their_public_key_y)

          @keys[:shared_secret]       = @keys[:their_public_key].multiply_by_scalar(@keys[:my_private_key]).x

          @keys[:their_authenticator] = _create_authenticator("client", @preshared_secret)
          @keys[:my_authenticator]    = _create_authenticator("server", @preshared_secret)

          @keys[:their_write_key]     = _create_key("client_write_key")
          @keys[:their_mac_key]       = _create_key("client_mac_key")
          @keys[:my_write_key]        = _create_key("server_write_key")
          @keys[:my_mac_key]          = _create_key("server_mac_key")

          return @keys[:my_public_key].x, @keys[:my_public_key].y
        end

        def set_their_authenticator!(their_authenticator)
          _ensure_shared_secret!()

          if(@keys[:their_authenticator] != their_authenticator)
            raise(Error, "Authenticator (pre-shared secret) doesn't match!")
          end

          @authenticated = true
        end

        def authenticate!()
          @authenticated = true
        end

        def authenticated?()
          return @authenticated
        end

        # We use this special internal function so we can try decrypting with different keys
        def _decrypt_packet_internal(keys, data)
          @l.debug("Encryptor: Decrypting a #{data.length}-byte packet")
          # Don't decrypt if we don't have a key set
#          if(@keys[:shared_secret].nil?)
#            return data
#          end

          # Parse out the important fields
          header, signature, nonce, encrypted_body = data.unpack("a5a6a2a*")

          # Check if it was truncated
          if(nonce.nil? || nonce.length < 2)
            raise(Error, "Invalid encrypted packet!")
          end

          # Check the signature
          correct_signature = SHA3::Digest::SHA256.digest(keys[:their_mac_key] + header + nonce + encrypted_body)
          if(correct_signature[0,6] != signature)
            raise(Error, "Invalid signature on incoming packet!")
          end

          # Check the nonce *after* checking the signature (otherwise, we might update the nonce to a bad value and Bad Stuff happens)
          nonce_int = nonce.unpack("n").pop()
          if(nonce_int < keys[:their_nonce])
            raise(Error, "Client tried to use an invalid nonce: #{nonce_int} < #{keys[:their_nonce]}")
          end
          keys[:their_nonce] = nonce_int

          # Decrypt the body
          body = Salsa20.new(keys[:their_write_key], nonce.rjust(8, "\0")).decrypt(encrypted_body)

          return header + body
        end

        def _encrypt_packet_internal(keys, data)
          @l.debug("Encryptor: Encrypting a #{data.length}-byte packet")

          # Split the packet into a header and a body
          header, body = data.unpack("a5a*")

          # Encode the nonce properly
          nonce = [keys[:my_nonce]].pack("n")

          # Encrypt the body
          encrypted_body = Salsa20.new(keys[:my_write_key], nonce.rjust(8, "\0")).encrypt(body)

          # Sign it
          signature = SHA3::Digest::SHA256.digest(keys[:my_mac_key] + header + nonce + encrypted_body)

          # Arrange things appropriately
          return [header, signature[0,6], nonce, encrypted_body].pack("a5a6a2a*")
        end

        # By doing this as a single operation, we can always be sure that we're encrypting data
        # with the same key the client use to encrypt data
        def decrypt_and_encrypt(d_data)
          _ensure_shared_secret!()

          ## Figure out which key to use
          keys = @keys
          begin
            d_data = _decrypt_packet_internal(keys, d_data)

            # If it was successfully decrypted, make sure the @old_keys will no longer work
            @old_keys = nil
          rescue Error => e
            # Attempt to fall back to old keys
            if(@old_keys.nil?)
              raise(e)
            end

            keys = @old_keys
            d_data = _decrypt_packet_internal(@old_keys, d_data)
          end

          # Send the decrypted data up and get the encrypted data back
          e_data = yield(d_data)

          return _encrypt_packet_internal(keys, e_data)
        end

        def to_s(keys = nil)
          keys = keys || @keys

          out = []
          out << "My private key:       #{Libs::CryptoHelper.bignum_to_text(@keys[:my_private_key])}"
          out << "My public key [x]:    #{Libs::CryptoHelper.bignum_to_text(@keys[:my_public_key].x)}"
          out << "My public key [y]:    #{Libs::CryptoHelper.bignum_to_text(@keys[:my_public_key].y)}"
          out << "Their public key [x]: #{Libs::CryptoHelper.bignum_to_text(@keys[:their_public_key].x)}"
          out << "Their public key [y]: #{Libs::CryptoHelper.bignum_to_text(@keys[:their_public_key].y)}"
          out << "Shared secret:        #{Libs::CryptoHelper.bignum_to_text(@keys[:shared_secret])}"
          out << ""
          out << "Their authenticator:  #{@keys[:their_authenticator].unpack("H*").pop()}"
          out << "My authenticator:     #{@keys[:my_authenticator].unpack("H*").pop()}"
          out << ""
          out << "Their write key: #{@keys[:their_write_key].unpack("H*").pop()}"
          out << "Their mac key:   #{@keys[:their_mac_key].unpack("H*").pop()}"
          out << "My write key:    #{@keys[:my_write_key].unpack("H*").pop()}"
          out << "My mac key:      #{@keys[:my_mac_key].unpack("H*").pop()}"
          out << ""
          out << "SAS: #{sas()}"

          return out.join("\n")
        end
      end
    end
  end
end
