# frozen_string_literal: true

module Seekrit
  # Base class for every error raised by this SDK.
  class Error < StandardError; end

  # A token, wrapped DEK, or secret ciphertext could not be parsed or decrypted.
  # Deliberately unspecific: a decrypt failure does not distinguish "wrong key"
  # from "tampered data" from "mismatched context".
  class CryptoError < Error; end

  # The resolve API returned a non-2xx response.
  class ApiError < Error
    # @return [Integer] HTTP status code.
    attr_reader :status
    # @return [String] error.code from the API body (e.g. "unauthorized",
    #   "forbidden", "not_found"), or "internal" if the body did not parse.
    attr_reader :code

    def initialize(status, code, message)
      @status = status
      @code = code
      super("#{status} #{code}: #{message}")
    end
  end
end
