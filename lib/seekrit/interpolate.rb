# frozen_string_literal: true

require_relative "errors"

module Seekrit
  # Secret references: ${OTHER_SECRET} inside a secret value.
  #
  # Expansion happens here, in-process, after the layers are merged — the API
  # only ever holds the ciphertext of the literal ${OTHER_SECRET} text. The rules
  # are fixed by the shared golden fixture (testdata/vectors.json, key
  # "interpolation"), which every seekrit client is tested against:
  #
  #   * ${NAME} becomes NAME's value from the same merged set, recursively.
  #   * NAME must look like an environment variable ([A-Za-z_][A-Za-z0-9_]*);
  #     anything else (${FOO:-bar}, ${1}) is left exactly as written.
  #   * A name that is not in the set is left literal and listed in +unresolved+,
  #     so a stored value containing e.g. ${GITHUB_SHA} keeps working.
  #   * $${NAME} is an escape for the literal text ${NAME}.
  #   * A reference cycle raises ReferenceError.
  module Interpolate
    REFERENCE_NAME = /\A[A-Za-z_][A-Za-z0-9_]*\z/.freeze

    # Cap on a single expanded value: nested references can multiply length.
    MAX_EXPANDED_LENGTH = 1_048_576

    # The outcome of expanding a variable set.
    #
    # @!attribute values
    #   @return [Hash{String=>String}] the set with every reference expanded
    # @!attribute expanded
    #   @return [Array<String>] names whose value had a reference expanded
    # @!attribute unresolved
    #   @return [Array<String>] referenced names absent from the set, sorted
    Interpolation = Struct.new(:values, :expanded, :unresolved)

    module_function

    # Split a value into literal runs and references — the single tokenizer the
    # rules above are expressed in terms of. Yields [reference, text]: for a
    # literal, +reference+ is nil; for a reference, +text+ is its raw ${NAME}
    # source (used verbatim when the name turns out to be absent).
    def scan(text)
      return enum_for(:scan, text) unless block_given?

      i = 0
      while i < text.length
        dollar = text.index("$", i)
        if dollar.nil?
          yield [nil, text[i..]]
          return
        end
        yield [nil, text[i...dollar]] if dollar > i

        # `$${` — escape: emit a literal `${` and skip all three characters, so
        # the `{NAME}` that follows can never be read as a reference.
        if text[dollar + 1, 2] == "${"
          yield [nil, "${"]
          i = dollar + 3
          next
        end

        close = text[dollar + 1] == "{" ? text.index("}", dollar + 2) : nil
        reference = close ? text[(dollar + 2)...close] : nil
        if reference && REFERENCE_NAME.match?(reference)
          yield [reference, text[dollar..close]]
          i = close + 1
          next
        end

        # A plain `$`, an unterminated `${`, or a non-name: literal. Advancing a
        # single character lets a `${` later in the run still be recognized.
        yield [nil, "$"]
        i = dollar + 1
      end
    end

    # Expand ${NAME} references throughout a merged variable set. The input hash
    # is never mutated.
    #
    # @param values [Hash{String=>String}]
    # @return [Interpolation]
    # @raise [Seekrit::ReferenceError] on a reference cycle or unbounded growth
    def interpolate_secrets(values)
      state = { resolved: {}, unresolved: {}, stack: [] }
      result = {}
      expanded = []
      values.each_key do |name|
        value = resolve_reference(name, values, state)
        result[name] = value
        expanded << name if value != values[name]
      end
      Interpolation.new(result, expanded, state[:unresolved].keys.sort)
    end

    # Expand one present name's value, memoized so each is expanded once.
    # @api private
    def resolve_reference(name, values, state)
      cached = state[:resolved][name]
      return cached if cached

      stack = state[:stack]
      at = stack.index(name)
      unless at.nil?
        chain = stack[at..] + [name]
        raise ReferenceError.new("CYCLE", "secret reference cycle: #{chain.join(' -> ')}")
      end

      stack.push(name)
      out = +""
      scan(values[name]) do |reference, text|
        if reference.nil?
          out << text
        elsif values.key?(reference)
          out << resolve_reference(reference, values, state)
        else
          state[:unresolved][reference] = true
          out << text
        end
      end
      stack.pop

      if out.length > MAX_EXPANDED_LENGTH
        raise ReferenceError.new("TOO_LARGE", "#{name} expands to more than #{MAX_EXPANDED_LENGTH} bytes")
      end

      state[:resolved][name] = out
      out
    end
  end
end
