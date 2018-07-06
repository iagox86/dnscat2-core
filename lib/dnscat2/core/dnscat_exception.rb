##
# dnscat_exception.rb
# Created July 1, 2013 (Canada Day!)
# By Ron Bowes
#
# See LICENSE.md
#
# Implements a simple exception class for dnscat2 protocol errors.
##

module Dnscat2
  module Core
    class DnscatException < ::StandardError
    end
  end
end
