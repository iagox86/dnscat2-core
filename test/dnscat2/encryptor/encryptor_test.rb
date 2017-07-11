# Encoding: ASCII-8BIT
require 'test_helper'
require 'dnscat2/core/encryptor/encryptor'
require 'dnscat2/core/encryptor/sas'

module Dnscat2
  module Core
    module Encryptor
      class EncryptorTest < ::Test::Unit::TestCase
        # These test keys were derived by running the original dnscat2 code and
        # copying them down - that ensures that we should have backwards
        # compatibility.
        def test_key_gen()
          encryptor = Encryptor.new(preshared_secret: "9ecaab6567438023e297cc746f83fa85")
          encryptor.set_their_public_key!(
            0xb3c8ef79b5e9d6c85dc820b861ad059b38bc005c3e2ec618ccccea1a89395747, # x
            0xc55e7c840eb1c027fdc9e7ca99800002456efb616abef4eba0785e523f870606, # y
            testing_my_private_key: 0x0476adc5399e9b201b88e17559a6607d8a9cc859acec5a65085eabdb7cb97acf
          )

          assert_equal(
            0x0476adc5399e9b201b88e17559a6607d8a9cc859acec5a65085eabdb7cb97acf,
            encryptor.keys[:my_private_key],
          )

          assert_equal(
            0x35eae03a2b07dbc49303bbda660477db394ca3cfc0f8cca928c76c5fa56ff227,
            encryptor.keys[:my_public_key].x,
          )

          assert_equal(
            0xd774910e46b59595d275dd13e4bfa4baa2ef904b30232a48d2030d5c39ae9932,
            encryptor.keys[:my_public_key].y,
          )

          assert_equal(
            0xb3c8ef79b5e9d6c85dc820b861ad059b38bc005c3e2ec618ccccea1a89395747,
            encryptor.keys[:their_public_key].x,
          )

          assert_equal(
            0xc55e7c840eb1c027fdc9e7ca99800002456efb616abef4eba0785e523f870606,
            encryptor.keys[:their_public_key].y,
          )

          assert_equal(
            0x3982d88abf14c35b0f0d3e972aa7ab661fb8bd7fcc98faee3b2dc78835f5dcc4,
            encryptor.keys[:shared_secret],
          )

          assert_equal(
            "3d28069eb84e1313359ba239240932ffce9baf62879c4c2b748409a9d1b9147f",
            encryptor.keys[:their_authenticator].unpack("H*").pop(),
          )

          assert_equal(
            "c087ab40cfdef67a5fecb2dca67d529798ec1d8818c88826634cec0b3de6c623",
            encryptor.keys[:my_authenticator].unpack("H*").pop(),
          )

          assert_equal(
            "3777f35cbb07de4e4a3caffbc294ebcf020a8ee5f2ac43472125b40c2149c253",
            encryptor.keys[:their_write_key].unpack("H*").pop(),
          )
          assert_equal(
            "b2eccdcd752c640af1ee2699d3c896f2c2a371697f2c2059c1f397db19f10898",
            encryptor.keys[:their_mac_key].unpack("H*").pop(),
          )
          assert_equal(
            "9587bdad4d8ed92d7889b1c9927a14a79b3d2b08e7a689a407ecc4f59870bd55",
            encryptor.keys[:my_write_key].unpack("H*").pop(),
          )
          assert_equal(
            "5f6fb8530f2019211215f178039bb732da071619125d3d10b92aed7e6966e707",
            encryptor.keys[:my_mac_key].unpack("H*").pop(),
          )
          assert_equal(
            "Flaunt Bask Pianos Pontic Spring Bulby",
            encryptor.sas(),
          )
        end

        def test_encrypt_decrypt()
          encryptor = Encryptor.new(preshared_secret: "58f3f65b5a37f05de02eeca1ace45006")
          encryptor.set_their_public_key!(
            0x7564eeb0f9db61af5059a74cf3bd28b59db5260f3d75b7cdfc44f1c1b991e9fd, # x
            0x5335a8b8a1a93e822b4292c197315d86873b42825e7b6c8c2e9f2d0d5cce0cb5, # y
            testing_my_private_key: 0xe64174833f47c0111befe5e6d8722ef410cf32ae1edb2ffc534dab0f5b60481a,
          )

					assert_equal(
            0x6d54c3b363b47845c9e8f812b35b419e5c47db0052ad004787008c7648911eb3,
            encryptor.keys[:shared_secret],
          )

          # A SYN message captured off the wire
          msg = "\xe1\x69\x00\xac\xbf\x46\x31\x7a\x4a\xc5\x7b\x00\x00\x36\x0b\x4b" +
                "\xa9\x14\xda\x21\xfe\x06\xe1\x5e\xaf\x11\xbe\x02\x4e\xdf\x4b\x47" +
                "\xe9\x4b\x60\x76"

          # Decrypt it, and encrypt a response
          encrypted = encryptor.decrypt_and_encrypt(msg) do |decrypted|
            expected = "" +
                "\xE1\x69\x00\xAC\xBF\x08\x37\x00\x01\x63\x6F\x6E\x73\x6F\x6C\x65" +
                "\x20\x28\x73\x69\x72\x76\x69\x6D\x65\x73\x29\x00"
            assert_equal(expected, decrypted)

            # The plaintext response
            "\xD0\x1B\x00\xAC\xBF\x45\x3D\x00\x00"
          end

          expected = "\xd0\x1b\x00\xac\xbf\x0a\xd4\x49\xd9\x63\x54\xff\xff\x4b\x1e\x55\x23"
          assert_equal(expected, encrypted)
        end

        def test_decrypt_encrypt_same_thing_twice()
          encryptor = Encryptor.new(preshared_secret: "58f3f65b5a37f05de02eeca1ace45006")
          encryptor.set_their_public_key!(
            0x7564eeb0f9db61af5059a74cf3bd28b59db5260f3d75b7cdfc44f1c1b991e9fd, # x
            0x5335a8b8a1a93e822b4292c197315d86873b42825e7b6c8c2e9f2d0d5cce0cb5, # y
            testing_my_private_key: 0xe64174833f47c0111befe5e6d8722ef410cf32ae1edb2ffc534dab0f5b60481a,
          )

					assert_equal(
            0x6d54c3b363b47845c9e8f812b35b419e5c47db0052ad004787008c7648911eb3,
            encryptor.keys[:shared_secret],
          )

          # A SYN message captured off the wire
          msg = "\xe1\x69\x00\xac\xbf\x46\x31\x7a\x4a\xc5\x7b\x00\x00\x36\x0b\x4b" +
                "\xa9\x14\xda\x21\xfe\x06\xe1\x5e\xaf\x11\xbe\x02\x4e\xdf\x4b\x47" +
                "\xe9\x4b\x60\x76"

          # Decrypt it, and encrypt a response
          encrypted = encryptor.decrypt_and_encrypt(msg) do |decrypted|
            # The plaintext response
            "\xD0\x1B\x00\xAC\xBF\x45\x3D\x00\x00"
          end

          # Now do it a second time - since the nonce didn't change, this should
          # work identically
          encrypted = encryptor.decrypt_and_encrypt(msg) do |decrypted|
            expected = "" +
                "\xE1\x69\x00\xAC\xBF\x08\x37\x00\x01\x63\x6F\x6E\x73\x6F\x6C\x65" +
                "\x20\x28\x73\x69\x72\x76\x69\x6D\x65\x73\x29\x00"
            assert_equal(expected, decrypted)

            # The plaintext response
            "\xD0\x1B\x00\xAC\xBF\x45\x3D\x00\x00"
          end

          expected = "\xd0\x1b\x00\xac\xbf\x0a\xd4\x49\xd9\x63\x54\xff\xff\x4b\x1e\x55\x23"
          assert_equal(expected, encrypted)
        end

        def test_authenticate()
          encryptor = Encryptor.new(preshared_secret: "d0e58099e8a0bc57cc5e104f68d7aab9")
          encryptor.set_their_public_key!(
            0x7508babc8f3d4d33654301d15697727db74c4b7977e2f006fd4c20dfe9ac9561, # x
            0xf331a01cb5ea22849c2560b903ff820ca8817b40ab849f4c2abb6cb4a9589509, # y
            testing_my_private_key: 0x6b5d97d4e6d6c56754622f231069d66385c359d7773a70b79faa71636b8c651a,
          )

          assert_false(encryptor.authenticated?)
          encryptor.set_their_authenticator!(
            "\x88\x23\xf3\x5f\xaa\xbf\x8b\xe4\xa0\xc7\xb8\x23\x56\x07\x8b\xb3" +
            "\x6a\x48\x21\x0e\xce\x23\x41\x6c\xcf\x8e\x75\xef\xd6\x08\x95\xf0"
          )
          assert_true(encryptor.authenticated?)
        end

        def test_bad_authenticate()
          encryptor = Encryptor.new(preshared_secret: "d0e58099e8a0bc57cc5e104f68d7aab9")
          encryptor.set_their_public_key!(
            0x7508babc8f3d4d33654301d15697727db74c4b7977e2f006fd4c20dfe9ac9561, # x
            0xf331a01cb5ea22849c2560b903ff820ca8817b40ab849f4c2abb6cb4a9589509, # y
            testing_my_private_key: 0x6b5d97d4e6d6c56754622f231069d66385c359d7773a70b79faa71636b8c651a,
          )

          e = assert_raises(Error) do
            encryptor.set_their_authenticator!(
              "\x41\x23\xf3\x5f\xaa\xbf\x8b\xe4\xa0\xc7\xb8\x23\x56\x07\x8b\xb3" +
              "\x6a\x48\x21\x0e\xce\x23\x41\x6c\xcf\x8e\x75\xef\xd6\x08\x95\xf0"
            )
          end
          assert_false(encryptor.authenticated?)
          assert_true(e.to_s.include?("Authenticator (pre-shared secret) doesn't match!"))
        end

        def test_manual_authenticate()
          encryptor = Encryptor.new(preshared_secret: "58f3f65b5a37f05de02eeca1ace45006")
          encryptor.set_their_public_key!(
            0x7564eeb0f9db61af5059a74cf3bd28b59db5260f3d75b7cdfc44f1c1b991e9fd, # x
            0x5335a8b8a1a93e822b4292c197315d86873b42825e7b6c8c2e9f2d0d5cce0cb5, # y
            testing_my_private_key: 0xe64174833f47c0111befe5e6d8722ef410cf32ae1edb2ffc534dab0f5b60481a,
          )
          assert_false(encryptor.authenticated?)
          encryptor.authenticate!()
          assert_true(encryptor.authenticated?)
        end

        def test_reject_lower_nonce()
          encryptor = Encryptor.new(preshared_secret: "58f3f65b5a37f05de02eeca1ace45006")
          encryptor.set_their_public_key!(
            0x7564eeb0f9db61af5059a74cf3bd28b59db5260f3d75b7cdfc44f1c1b991e9fd, # x
            0x5335a8b8a1a93e822b4292c197315d86873b42825e7b6c8c2e9f2d0d5cce0cb5, # y
            testing_my_private_key: 0xe64174833f47c0111befe5e6d8722ef410cf32ae1edb2ffc534dab0f5b60481a,
          )

					assert_equal(
            0x6d54c3b363b47845c9e8f812b35b419e5c47db0052ad004787008c7648911eb3,
            encryptor.keys[:shared_secret],
          )

          # Set the nonce to 1
          msg = "\xe1\x69\x00\xac\xbf\x10\x72\x34\x2b\x2f\xdf\x00\x01\x36\x0b\x4b" +
                "\xa9\x14\xda\x21\xfe\x06\xe1\x5e\xaf\x11\xbe\x02\x4e\xdf\x4b\x47" +
                "\xe9\x4b\x60\x76"

          # Decrypt it, and encrypt a response
          encryptor.decrypt_and_encrypt(msg) do
            ""
          end

          # Now try with a 0 nonce
          msg = "\xe1\x69\x00\xac\xbf\x46\x31\x7a\x4a\xc5\x7b\x00\x00\x36\x0b\x4b" +
                "\xa9\x14\xda\x21\xfe\x06\xe1\x5e\xaf\x11\xbe\x02\x4e\xdf\x4b\x47" +
                "\xe9\x4b\x60\x76"
          err = assert_raises(Error) do
            encryptor.decrypt_and_encrypt(msg) do
              ""
            end
          end

          assert_not_nil(err.to_s.include?('invalid nonce'))
        end

        def test_encrypt_decrypt_change_keys()
          # Set to one key
          encryptor = Encryptor.new(preshared_secret: "58f3f65b5a37f05de02eeca1ace45006")
          encryptor.set_their_public_key!(
            0x7564eeb0f9db61af5059a74cf3bd28b59db5260f3d75b7cdfc44f1c1b991e9fd, # x
            0x5335a8b8a1a93e822b4292c197315d86873b42825e7b6c8c2e9f2d0d5cce0cb5, # y
            testing_my_private_key: 0xe64174833f47c0111befe5e6d8722ef410cf32ae1edb2ffc534dab0f5b60481a,
          )

          # Set to a new key
          encryptor.set_their_public_key!(
            0xb3c8ef79b5e9d6c85dc820b861ad059b38bc005c3e2ec618ccccea1a89395747, # x
            0xc55e7c840eb1c027fdc9e7ca99800002456efb616abef4eba0785e523f870606, # y
            testing_my_private_key: 0x0476adc5399e9b201b88e17559a6607d8a9cc859acec5a65085eabdb7cb97acf
          )

          # Verify that we aren't using the original key pair
					assert_not_equal(
            0x6d54c3b363b47845c9e8f812b35b419e5c47db0052ad004787008c7648911eb3,
            encryptor.keys[:shared_secret],
          )

          # Try to decrypt data that was encrypted with the first key
          msg = "\xe1\x69\x00\xac\xbf\x46\x31\x7a\x4a\xc5\x7b\x00\x00\x36\x0b\x4b" +
                "\xa9\x14\xda\x21\xfe\x06\xe1\x5e\xaf\x11\xbe\x02\x4e\xdf\x4b\x47" +
                "\xe9\x4b\x60\x76"
          encrypted = encryptor.decrypt_and_encrypt(msg) do |decrypted|
            expected = "" +
                "\xE1\x69\x00\xAC\xBF\x08\x37\x00\x01\x63\x6F\x6E\x73\x6F\x6C\x65" +
                "\x20\x28\x73\x69\x72\x76\x69\x6D\x65\x73\x29\x00"
            assert_equal(expected, decrypted)

            # The plaintext response
            "\xD0\x1B\x00\xAC\xBF\x45\x3D\x00\x00"
          end

          expected = "\xd0\x1b\x00\xac\xbf\x0a\xd4\x49\xd9\x63\x54\xff\xff\x4b\x1e\x55\x23"
          assert_equal(expected, encrypted)

          # Now we "confirm" the new key
          msg = "\xe1\x69\x00\xac\xbf\x7d\xa7\x40\x90\x27\x99\x00\x00\x41\x41\x41"
          encrypted = encryptor.decrypt_and_encrypt(msg) do |decrypted|
            ''
          end

          # Now if we try the first key again, it should fail
          msg = "\xe1\x69\x00\xac\xbf\x46\x31\x7a\x4a\xc5\x7b\x00\x00\x36\x0b\x4b" +
                "\xa9\x14\xda\x21\xfe\x06\xe1\x5e\xaf\x11\xbe\x02\x4e\xdf\x4b\x47" +
                "\xe9\x4b\x60\x76"
          e = assert_raises(Error) do
            encryptor.decrypt_and_encrypt(msg) do |decrypted|
            end
          end
          assert_true(e.to_s.include?('Invalid signature'))
        end

        def test_reject_identical_key_cycle()
          # Set to one key
          encryptor = Encryptor.new(preshared_secret: "58f3f65b5a37f05de02eeca1ace45006")
          encryptor.set_their_public_key!(
            0x7564eeb0f9db61af5059a74cf3bd28b59db5260f3d75b7cdfc44f1c1b991e9fd, # x
            0x5335a8b8a1a93e822b4292c197315d86873b42825e7b6c8c2e9f2d0d5cce0cb5, # y
          )

          # Try to set it to the same key - would be a security problem
          e = assert_raises(Error) do
            encryptor.set_their_public_key!(
              0x7564eeb0f9db61af5059a74cf3bd28b59db5260f3d75b7cdfc44f1c1b991e9fd, # x
              0x5335a8b8a1a93e822b4292c197315d86873b42825e7b6c8c2e9f2d0d5cce0cb5, # y
            )
          end
          assert_true(e.to_s.include?('Attempted to cycle to the same key'))
        end

        def test_truncated()
          encryptor = Encryptor.new(preshared_secret: "58f3f65b5a37f05de02eeca1ace45006")
          encryptor.set_their_public_key!(
            0x7564eeb0f9db61af5059a74cf3bd28b59db5260f3d75b7cdfc44f1c1b991e9fd, # x
            0x5335a8b8a1a93e822b4292c197315d86873b42825e7b6c8c2e9f2d0d5cce0cb5, # y
          )

          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00\xac\xbfAAAAAA\x00") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00\xac\xbfAAAAAA") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00\xac\xbfAAAAA") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00\xac\xbfAAAA") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00\xac\xbfAAA") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00\xac\xbfAA") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00\xac\xbfA") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00\xac\xbf") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00\xac") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69\x00") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1\x69") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("\xe1") {} }
          assert_raises(Error) { encryptor.decrypt_and_encrypt("") {} }
        end

        def test_bad_signature()
          encryptor = Encryptor.new(preshared_secret: "58f3f65b5a37f05de02eeca1ace45006")
          encryptor.set_their_public_key!(
            0x7564eeb0f9db61af5059a74cf3bd28b59db5260f3d75b7cdfc44f1c1b991e9fd, # x
            0x5335a8b8a1a93e822b4292c197315d86873b42825e7b6c8c2e9f2d0d5cce0cb5, # y
            testing_my_private_key: 0xe64174833f47c0111befe5e6d8722ef410cf32ae1edb2ffc534dab0f5b60481a,
          )

          msg = "\xe1\x69\x00\xac\xbfAAAAAA\x00\x00"
          e = assert_raises(Error) do
            encryptor.decrypt_and_encrypt(msg) do |decrypted|
            end
          end

          assert_true(e.to_s.include?('Invalid signature'))
        end

        def test_bad_state()
          encryptor = Encryptor.new(preshared_secret: "58f3f65b5a37f05de02eeca1ace45006")
          e = assert_raises(Error) do
            encryptor.decrypt_and_encrypt('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') {}
          end
          assert_true(e.to_s.include?('State problem'))
        end

        def test_to_s()
          encryptor = Encryptor.new(preshared_secret: "d0e58099e8a0bc57cc5e104f68d7aab9")
          encryptor.set_their_public_key!(
            0x7508babc8f3d4d33654301d15697727db74c4b7977e2f006fd4c20dfe9ac9561, # x
            0xf331a01cb5ea22849c2560b903ff820ca8817b40ab849f4c2abb6cb4a9589509, # y
            testing_my_private_key: 0x6b5d97d4e6d6c56754622f231069d66385c359d7773a70b79faa71636b8c651a,
          )

          expected = "" +
            "My private key:       6b5d97d4e6d6c56754622f231069d66385c359d7773a70b79faa71636b8c651a\n" +
            "My public key [x]:    db2405e48f73aa44b7dfcae3404955a01efaf62c81e471fecff0778cbee832fb\n" +
            "My public key [y]:    86233b9e7590d548cd5f3e83aa0fb449f36cafa1f913584f08c605fc306d6524\n" +
            "Their public key [x]: 7508babc8f3d4d33654301d15697727db74c4b7977e2f006fd4c20dfe9ac9561\n" +
            "Their public key [y]: f331a01cb5ea22849c2560b903ff820ca8817b40ab849f4c2abb6cb4a9589509\n" +
            "Shared secret:        3ca2921183b02df07c2d0d8b7678a433bf25da1ebdf6308b548d87253979f49d\n" +
            "\n" +
            "Their authenticator:  8823f35faabf8be4a0c7b82356078bb36a48210ece23416ccf8e75efd60895f0\n" +
            "My authenticator:     5c85f4a8d872dfc9e60f3e9bd426f69e4be9cfac546642ab37203e5f5a01014d\n" +
            "\n" +
            "Their write key: c41cd16da0ff7d792f72350f1eaec86598ec84008e7f5a0b9e4ae0a7d72086e9\n" +
            "Their mac key:   3bad01c0f0d80fdeb3ce341c044df9420aa85795335579c0b50c282965944c8e\n" +
            "My write key:    a0fa3c12e5d9e005475a960648033c5440a6a3ee6cc6361d104e566551b80586\n" +
            "My mac key:      5505bb71a66203e106df6f63899d19c5c360b0dcd2a47b085d87d35544b98c21\n" +
            "\n" +
            "SAS: Convoy Stinty Redear Horror Tubule Barret"

          assert_equal(expected, encryptor.to_s())
        end
      end
    end
  end
end
