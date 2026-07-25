# frozen_string_literal: true

# Cross-implementation parity: decrypt the shared golden vectors and assert we
# recover exactly what the canonical @seekrit/crypto (WebCrypto) produced.
#
# Plain script (no test-framework dependency): ruby test/test_vectors.rb

require "json"
$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "seekrit/sdk"

VECTORS = JSON.parse(File.read(File.expand_path("../testdata/vectors.json", __dir__)))

@failures = 0
def check(name)
  yield
  puts "  ok  #{name}"
rescue StandardError => e
  @failures += 1
  puts "FAIL  #{name}\n      #{e.class}: #{e.message}"
end

def assert_equal(expected, actual)
  return if expected == actual

  raise "expected #{expected.inspect}, got #{actual.inspect}"
end

key = Seekrit::Crypto::TokenKey.parse(VECTORS["token"])

check("materialize matches expected") do
  merged = Seekrit::Crypto.materialize(VECTORS["resolve"], key)
  assert_equal(VECTORS["expectedManagedValues"], merged)
end

check("app layer wins over group") do
  merged = Seekrit::Crypto.materialize(VECTORS["resolve"], key)
  assert_equal("from-app", merged["SHARED"])
end

check("unicode and empty round-trip") do
  merged = Seekrit::Crypto.materialize(VECTORS["resolve"], key)
  assert_equal("héllo-🌍-\n-tab\tend", merged["UNICODE"])
  assert_equal("", merged["EMPTY"])
  raise "UNICODE not UTF-8" unless merged["UNICODE"].encoding == Encoding::UTF_8
end

check("secret references expand over the merged set") do
  merged = Seekrit::Crypto.materialize(VECTORS["resolve"], key)
  assert_equal("url=postgres://group/db;shared=from-app", merged["REFERENCING"])
  assert_equal("${SHARED}", merged["ESCAPED_REF"])
  assert_equal("build-${NOT_A_SECRET}", merged["DANGLING_REF"])
end

check("interpolate: false returns the stored text") do
  merged = Seekrit::Crypto.materialize(VECTORS["resolve"], key, interpolate: false)
  assert_equal("url=${DATABASE_URL};shared=${SHARED}", merged["REFERENCING"])
end

VECTORS["interpolation"]["cases"].each do |testcase|
  check("interpolation: #{testcase['name']}") do
    out = Seekrit::Interpolate.interpolate_secrets(testcase["input"])
    assert_equal(testcase["expected"], out.values)
    assert_equal(testcase["unresolved"], out.unresolved)
  end
end

VECTORS["interpolation"]["cycles"].each do |testcase|
  check("interpolation rejects: #{testcase['name']}") do
    begin
      Seekrit::Interpolate.interpolate_secrets(testcase["input"])
      raise "expected a cycle error"
    rescue Seekrit::ReferenceError
      # expected
    end
  end
end

check("tampered grant is rejected") do
  # A single-character flip in the wrapped-DEK ciphertext must fail the GCM tag,
  # not silently yield a wrong value.
  tampered = JSON.parse(JSON.generate(VECTORS["resolve"]))
  blob = tampered["layers"][0]["wrappedDek"]
  last = blob[-1]
  tampered["layers"][0]["wrappedDek"] = blob[0...-1] + (last == "A" ? "B" : "A")
  begin
    Seekrit::Crypto.materialize(tampered, key)
    raise "expected decryption to fail on tampered grant"
  rescue Seekrit::CryptoError
    # expected
  end
end

if @failures.positive?
  warn "\n#{@failures} test(s) failed"
  exit 1
end
puts "\nall vector tests passed"
