# seekrit — Ruby SDK

Read-path SDK for [seekrit](https://seekrit.dev). Authenticate with a service
token, resolve your environment, and get **decrypted** secrets — the API only
ever returns ciphertext; decryption happens in your process.

> This repo is a **read-only mirror** published from seekrit's monorepo so the
> code that holds your token and decrypts plaintext is auditable. Don't commit
> here — it's overwritten on each sync. Issues and PRs welcome.

## Install

```sh
gem install seekrit-sdk
```

Or in a Gemfile:

```ruby
gem "seekrit-sdk"
```

Requires Ruby 3.0+. **No runtime dependencies** — uses only the standard
library (`openssl`, `net/http`, `json`).

## Usage

The gem is `seekrit-sdk`; the module is `Seekrit`. Require it as `seekrit/sdk`
(or `seekrit` — both work):

```ruby
require "seekrit/sdk"

client = Seekrit::Client.new       # token from ENV["SEEKRIT_TOKEN"]
secrets = client.resolve           # { "DATABASE_URL" => "postgres://…", … }

db_url = client.get("DATABASE_URL")
api_key = client.get("API_KEY", "")
```

Load everything into `ENV`:

```ruby
Seekrit.load_env!                  # existing ENV vars win by default
ENV["DATABASE_URL"]                # => "postgres://…"
```

### Rails

The gem ships a Railtie. Opt in from `config/application.rb` or an initializer:

```ruby
config.seekrit.autoload = true     # load $SEEKRIT_TOKEN's secrets into ENV on boot
config.seekrit.override = false    # keep existing ENV vars (default)
```

Nothing hits the network at boot unless `autoload` is set.

### Configuration

| Keyword | Env var | Default |
| --- | --- | --- |
| `token:` | `SEEKRIT_TOKEN` | — (required) |
| `api_url:` | `SEEKRIT_API_URL` | `https://api.seekrit.dev` |
| `with:` | — | `{}` |
| `open_timeout:` / `read_timeout:` | — | `10` / `30` (seconds) |

A service token binds to a single app environment (plus its composed group
slices). Pass `with:` to pull a different environment slice of a composed group:

```ruby
Seekrit::Client.new(with: { "shared" => "dev" }).resolve
```

### Errors

- `Seekrit::ApiError` — non-2xx from the API; has `#status` and `#code`
  (`"unauthorized"`, `"forbidden"`, `"not_found"`, …).
- `Seekrit::CryptoError` — a token or ciphertext could not be parsed/decrypted.
- `Seekrit::Error` — base class (also covers network failures).

`#resolve` is **fail-closed**: any resolve or decrypt failure raises rather than
returning partial results.

## Secret references

A secret's value may reference another with `${OTHER_SECRET}`. References are
stored literally and expanded here, after the layers are merged — so a reference
picks up whichever layer won that name, and rotating the referenced secret
updates every value that uses it. `$${OTHER_SECRET}` is a literal; an unknown
name is left as written; a reference cycle raises. Full rules:
[seekrit.dev/docs/guides/references](https://seekrit.dev/docs/guides/references).

```ruby
client = Seekrit::Client.new(interpolate: false) # get the stored text instead
```

## Zero-knowledge

`GET /v1/resolve` returns ciphertext plus a data-encryption key wrapped to your
token's public key. This SDK recovers the token's private key, unwraps the DEK
(ECDH P-256 → HKDF-SHA256 → AES-256-GCM), and decrypts each secret
(AES-256-GCM, AAD-bound to `environmentId/NAME`) — the exact scheme used by the
CLI, `seekrit run`, and every other seekrit client. See
[seekrit.dev/docs](https://seekrit.dev/docs/concepts/encryption).

## License

MIT

## Service token v2

Keep one `SEEKRIT_TOKEN`: `skt_<id>_v2.<auth-secret>.<private-key>`.
The client sends only `skt_<id>_v2.<auth-secret>` to the API and uses the private
key locally to decrypt. Legacy tokens are rejected before any API request;
upgrade clients and replace legacy tokens through the dashboard. A stolen
HTTP credential cannot decrypt environment payloads, but stealing the full
local bundle still exposes the private key. Treat the full bundle as a secret.
