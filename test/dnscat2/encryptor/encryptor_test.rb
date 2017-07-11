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

        def test_authenticate()
        end

        def test_manual_authenticate()
        end

        def test_encrypt_decrypt()
        end

        def test_encrypt_decrypt_change_keys()
        end

        def test_encrypt_decrypt_fail()
        end
      end
    end
  end
end
