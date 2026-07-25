# frozen_string_literal: true

module Seekrit
  # Base class for every error raised by this SDK.
  class Error < StandardError; end

  # A token, wrapped DEK, or secret ciphertext could not be parsed or decrypted.
  # Deliberately unspecific: a decrypt failure does not distinguish "wrong key"
  # from "tampered data" from "mismatched context".
  class CryptoError < Error; end

  # A ${OTHER_SECRET} reference could not be expanded: a cycle, or an expansion
  # that grows without bound. An *unknown* reference is not an error — it is left
  # as literal text (see Seekrit::Interpolate.interpolate_secrets).
  class ReferenceError < Error
    # @return [String] "CYCLE" or "TOO_LARGE".
    attr_reader :code

    def initialize(code, message)
      @code = code
      super(message)
    end
  end

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
