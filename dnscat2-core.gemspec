# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'dnscat2/core/version'

Gem::Specification.new do |spec|
  spec.name          = "dnscat2-core"
  spec.version       = Dnscat2::Core::VERSION
  spec.authors       = ["iagox86"]
  spec.email         = ["ron-git@skullsecurity.org"]

  spec.summary       = 'A DNS-tunneling library designed for command and control'
  spec.description   = 'A DNS-tunneling library designed for command and control'
  spec.homepage      = "https://github.com/iagox86/dnscat2-core"

  # Prevent pushing this gem to RubyGems.org by setting 'allowed_push_host', or
  # delete this section to allow pushing this gem to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler",   "~> 1.11"
  spec.add_development_dependency "rake",      "~> 10.0"
  spec.add_development_dependency "simplecov", "~> 0.14.1"
  spec.add_development_dependency "test-unit", "~> 3.2.8"

  spec.add_dependency "ecdsa",      "~> 1.2.0"
  spec.add_dependency "hexhelper",  "~> 0.0.2"
  spec.add_dependency "nesser",     "~> 0.0.4"
  spec.add_dependency "salsa20",    "~> 0.1.2"
  spec.add_dependency "sha3",       "~> 1.0.1"
  spec.add_dependency "singlogger", "~> 0.0.0"
  spec.add_dependency "base32",     "~> 0.3.2"
end
