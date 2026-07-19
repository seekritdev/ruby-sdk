# frozen_string_literal: true

require_relative "lib/seekrit/version"

Gem::Specification.new do |spec|
  spec.name = "seekrit-sdk"
  spec.version = Seekrit::VERSION
  spec.summary = "Read-path SDK for seekrit — resolve and decrypt secrets client-side with a service token."
  spec.description = <<~DESC
    Read-path SDK for seekrit, the zero-knowledge secrets manager. Authenticate
    with a service token, resolve your environment, and get decrypted secrets —
    the API only ever returns ciphertext; decryption happens in your process.
    Uses only the Ruby standard library (openssl, net/http, json). Optional Rails
    integration included. Require as "seekrit" or "seekrit/sdk"; the module is
    Seekrit.
  DESC
  spec.authors = ["seekrit"]
  spec.homepage = "https://seekrit.dev"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata = {
    "homepage_uri" => "https://seekrit.dev",
    "documentation_uri" => "https://seekrit.dev/docs",
    "source_code_uri" => "https://github.com/seekritdev/ruby-sdk",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir["lib/**/*.rb", "testdata/vectors.json", "README.md", "LICENSE"]
  spec.require_paths = ["lib"]
end
