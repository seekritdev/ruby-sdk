# frozen_string_literal: true

# Entrypoint matching the `seekrit-sdk` gem name, so `require "seekrit/sdk"`
# and Bundler's auto-require of `gem "seekrit-sdk"` both work. `require "seekrit"`
# works too — both load the same code, and the module is `Seekrit`.
require_relative "../seekrit"
