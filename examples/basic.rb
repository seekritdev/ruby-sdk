# frozen_string_literal: true

# Resolve and print secret names (not values) for the token in $SEEKRIT_TOKEN.
#
#   export SEEKRIT_TOKEN=skt_...
#   ruby examples/basic.rb

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "seekrit/sdk"

secrets = Seekrit::Client.new.resolve
puts "resolved #{secrets.size} secret(s):"
secrets.keys.sort.each { |name| puts "  - #{name}" }
