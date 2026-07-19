# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

require_relative "crypto"
require_relative "errors"

module Seekrit
  # A read-only seekrit client bound to one service token. A service token
  # selects exactly one app environment (plus its composed group slices).
  #
  #   client = Seekrit::Client.new           # token from ENV["SEEKRIT_TOKEN"]
  #   secrets = client.resolve               # { "DATABASE_URL" => "...", ... }
  class Client
    DEFAULT_API_URL = "https://api.seekrit.dev"

    # @param token [String, nil] skt_... service token; defaults to ENV["SEEKRIT_TOKEN"].
    # @param api_url [String, nil] API base URL; defaults to ENV["SEEKRIT_API_URL"] or the hosted API.
    # @param with [Hash] {group_slug => env_slug} overrides (the ?with= override).
    # @param open_timeout [Numeric] connection timeout, seconds.
    # @param read_timeout [Numeric] read timeout, seconds.
    def initialize(token: nil, api_url: nil, with: {}, open_timeout: 10, read_timeout: 30)
      @token = token || ENV["SEEKRIT_TOKEN"]
      raise Error, "no service token: pass token: or set SEEKRIT_TOKEN" unless @token && !@token.empty?

      @key = Crypto::TokenKey.parse(@token) # fail fast on a bad token
      @api_url = (api_url || ENV["SEEKRIT_API_URL"] || DEFAULT_API_URL).sub(%r{/+\z}, "")
      @with = with || {}
      @open_timeout = open_timeout
      @read_timeout = read_timeout
    end

    # Fetch, decrypt, and merge; returns { "NAME" => value }. Fail-closed.
    # @return [Hash{String=>String}]
    def resolve
      Crypto.materialize(fetch, @key)
    end

    # Resolve and return a single secret's value, or +default+ if absent.
    def get(name, default = nil)
      resolve.fetch(name, default)
    end

    # Load resolved secrets into +env+ (default ENV). Existing keys are kept
    # unless +override:+ is true. Returns the resolved secrets.
    def into_env(env = ENV, override: false)
      merged = resolve
      merged.each do |name, value|
        env[name] = value if override || !env.key?(name)
      end
      merged
    end

    private

    def fetch
      uri = URI("#{@api_url}/v1/resolve")
      unless @with.empty?
        uri.query = URI.encode_www_form(@with.sort.map { |group, env| ["with", "#{group}:#{env}"] })
      end

      request = Net::HTTP::Get.new(uri)
      request["authorization"] = "Bearer #{@token}"
      request["accept"] = "application/json"

      response = Net::HTTP.start(
        uri.host, uri.port,
        use_ssl: uri.scheme == "https",
        open_timeout: @open_timeout, read_timeout: @read_timeout
      ) { |http| http.request(request) }

      status = response.code.to_i
      raise api_error(status, response.body) unless (200..299).cover?(status)

      JSON.parse(response.body)
    rescue SocketError, Timeout::Error, IOError => e
      raise Error, "resolve request failed: #{e.message}"
    end

    def api_error(status, body)
      code = "internal"
      message = "HTTP #{status}"
      begin
        error = JSON.parse(body)["error"]
        if error.is_a?(Hash) && error["code"]
          code = error["code"]
          message = error["message"] || message
        end
      rescue JSON::ParserError, TypeError
        # non-JSON body — keep the fallback
      end
      ApiError.new(status, code, message)
    end
  end

  # Convenience: load a token's secrets straight into ENV.
  #   Seekrit.load_env!
  def self.load_env!(**opts)
    override = opts.delete(:override) { false }
    Client.new(**opts).into_env(ENV, override: override)
  end
end
