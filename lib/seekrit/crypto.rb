# frozen_string_literal: true

require "openssl"
require "base64"

module Seekrit
  # Zero-knowledge read path, byte-compatible with @seekrit/crypto and
  # crates/seekrit-core. Three steps:
  #
  #   1. Recover the service token's P-256 private key  (TokenKey.parse).
  #   2. Unwrap each environment DEK                     (TokenKey#unwrap_dek).
  #   3. Decrypt each secret                             (Crypto.decrypt_secret).
  #
  # Blob formats (all segments base64url, no padding):
  #   token       skt_<id>_<pkcs8 private key>
  #   wrapped DEK wd1.<ephemeral pub (raw SEC1)>.<hkdf salt>.<iv>.<ciphertext||tag>
  #   secret      sc1.<iv>.<ciphertext||tag>
  module Crypto
    HKDF_INFO = "seekrit/wrap-dek/v1"
    CURVE = "prime256v1" # NIST P-256 / secp256r1
    # Only the first two underscores are separators; the key segment may contain "_".
    TOKEN_RE = /\A(skt_[0-9A-Za-z]+)_([A-Za-z0-9_-]+)\z/.freeze

    module_function

    def b64url_decode(text)
      Base64.urlsafe_decode64(text + ("=" * ((4 - (text.length % 4)) % 4)))
    end

    def split_blob(blob, prefix, segments)
      parts = blob.split(".")
      unless parts[0] == prefix
        raise CryptoError, %(expected a "#{prefix}" blob, got "#{parts[0]}")
      end
      if parts.length != segments + 1 || parts.any?(&:empty?)
        raise CryptoError, %(malformed "#{prefix}" blob)
      end

      parts[1..]
    end

    # AAD binding a secret ciphertext to its environment and name.
    def secret_aad(environment_id, name)
      "#{environment_id}/#{name}"
    end

    # HKDF-SHA256 (RFC 5869), implemented with HMAC so it works on every Ruby /
    # OpenSSL / LibreSSL build regardless of OpenSSL::KDF.hkdf availability.
    def hkdf_sha256(ikm, salt, info, length)
      prk = OpenSSL::HMAC.digest("SHA256", salt, ikm)
      okm = +""
      block = +""
      counter = 0
      while okm.bytesize < length
        counter += 1
        block = OpenSSL::HMAC.digest("SHA256", prk, block + info + [counter].pack("C"))
        okm << block
      end
      okm[0, length]
    end

    def aes_gcm_decrypt(key, iv, ciphertext_and_tag, aad)
      raise CryptoError, "ciphertext too short" if ciphertext_and_tag.bytesize < 16

      tag = ciphertext_and_tag[-16, 16]
      ciphertext = ciphertext_and_tag[0...-16]
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      cipher.auth_tag = tag
      # GCM with no AAD == empty AAD; skip the call so a zero-length AAD never
      # trips broken bindings (e.g. some LibreSSL builds).
      cipher.auth_data = aad unless aad.nil? || aad.empty?
      cipher.update(ciphertext) + cipher.final
    end

    # The P-256 private key recovered from a skt_... service token.
    class TokenKey
      attr_reader :token_id

      def initialize(token_id, ec_key)
        @token_id = token_id
        @ec_key = ec_key
      end

      def self.parse(token)
        match = Crypto::TOKEN_RE.match(token)
        raise CryptoError, "not a valid seekrit service token" unless match

        der = Crypto.b64url_decode(match[2])
        ec_key = begin
          key = OpenSSL::PKey.read(der)
          raise CryptoError, "service token key is not an EC private key" unless key.is_a?(OpenSSL::PKey::EC)

          key
        rescue OpenSSL::PKey::PKeyError, ArgumentError
          begin
            OpenSSL::PKey::EC.new(der)
          rescue StandardError
            raise CryptoError, "service token private key is corrupted"
          end
        end
        new(match[1], ec_key)
      end

      # Recover a 32-byte environment DEK from a wd1. blob.
      def unwrap_dek(wrapped)
        eph_b64, salt_b64, iv_b64, ct_b64 = Crypto.split_blob(wrapped, "wd1", 4)
        eph = Crypto.b64url_decode(eph_b64)
        salt = Crypto.b64url_decode(salt_b64)
        iv = Crypto.b64url_decode(iv_b64)
        ct = Crypto.b64url_decode(ct_b64)

        group = OpenSSL::PKey::EC::Group.new(Crypto::CURVE)
        peer_point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(eph, 2))
        shared = @ec_key.dh_compute_key(peer_point)
        wrapping_key = Crypto.hkdf_sha256(shared, salt, Crypto::HKDF_INFO, 32)

        dek = begin
          Crypto.aes_gcm_decrypt(wrapping_key, iv, ct, "")
        rescue OpenSSL::Cipher::CipherError
          raise CryptoError, "DEK unwrap failed: wrong private key or tampered grant"
        end
        raise CryptoError, "unwrapped DEK has wrong length" unless dek.bytesize == 32

        dek
      end
    end

    # Decrypt an sc1. secret ciphertext to its UTF-8 plaintext.
    def decrypt_secret(dek, blob, aad)
      iv_b64, ct_b64 = split_blob(blob, "sc1", 2)
      iv = b64url_decode(iv_b64)
      ct = b64url_decode(ct_b64)
      plaintext = begin
        aes_gcm_decrypt(dek, iv, ct, aad)
      rescue OpenSSL::Cipher::CipherError
        raise CryptoError, "secret decryption failed: wrong key, tampered data, or mismatched context"
      end
      plaintext.force_encoding(Encoding::UTF_8)
    end

    # Decrypt every layer and merge by precedence. Layers arrive lowest
    # precedence first (composed groups, then the app environment); later layers
    # overwrite earlier ones on a name collision.
    def materialize(resolve_response, key)
      merged = {}
      resolve_response["layers"].each do |layer|
        dek = key.unwrap_dek(layer["wrappedDek"])
        env_id = layer["environmentId"]
        layer["secrets"].each do |secret|
          merged[secret["name"]] = decrypt_secret(dek, secret["ciphertext"], secret_aad(env_id, secret["name"]))
        end
      end
      merged
    end
  end
end
