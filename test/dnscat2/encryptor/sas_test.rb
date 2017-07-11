# Encoding: ASCII-8BIT
require 'test_helper'
require 'dnscat2/core/encryptor/encryptor'
require 'dnscat2/core/encryptor/sas'

module Dnscat2
  module Core
    module Encryptor
      class SASTest < ::Test::Unit::TestCase
        def test_sas()
          sas = SAS.get_sas("test")
          assert_equal('Tattoo Amuse Stilt Fate Ache Upcurl', sas)

          sas = SAS.get_sas("test2")
          assert_equal('Foxes Kelpy Hither Visas Suited Pedal', sas)
        end
      end
    end
  end
end
