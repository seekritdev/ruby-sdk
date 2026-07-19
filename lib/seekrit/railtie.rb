# frozen_string_literal: true

require_relative "client"

module Seekrit
  # Optional Rails integration. Loaded automatically when Rails is present
  # (see lib/seekrit.rb). Opt-in: resolved secrets are only loaded into ENV if
  # you enable it, so nothing hits the network at boot unless you ask.
  #
  #   # config/application.rb (or an initializer)
  #   config.seekrit.autoload = true      # load $SEEKRIT_TOKEN's secrets into ENV on boot
  #   config.seekrit.override = false     # keep existing ENV vars (default)
  #
  # Or call it yourself whenever you like:
  #
  #   Seekrit.load_env!
  class Railtie < ::Rails::Railtie
    config.seekrit = ActiveSupport::OrderedOptions.new
    config.seekrit.autoload = false
    config.seekrit.override = false

    initializer "seekrit.load_env", before: :load_environment_config do |app|
      cfg = app.config.seekrit
      Seekrit.load_env!(override: cfg.override) if cfg.autoload && ENV["SEEKRIT_TOKEN"]
    end
  end
end
