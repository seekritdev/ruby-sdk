# frozen_string_literal: true

require_relative "seekrit/version"
require_relative "seekrit/errors"
require_relative "seekrit/interpolate"
require_relative "seekrit/crypto"
require_relative "seekrit/client"

# seekrit — read-path SDK for the zero-knowledge secrets manager.
#
#   require "seekrit"
#
#   client = Seekrit::Client.new     # token from ENV["SEEKRIT_TOKEN"]
#   secrets = client.resolve         # { "DATABASE_URL" => "...", ... }
#
# Secrets are decrypted in-process; the API only ever sees ciphertext.
module Seekrit
  # Load the Rails integration only when Rails is present.
  require_relative "seekrit/railtie" if defined?(::Rails::Railtie)
end
