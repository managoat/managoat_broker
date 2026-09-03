defmodule Managoat.Broker.Rule do
  @moduledoc """
  One rule of a session: requests to hosts matching `pattern` get this
  credential, in this shape.

  The host defines what a rule is *for* (a tenant's binding, a catalog
  default, an allowed host under `deny`) and maps it to one of these at
  session creation. The proxy sees only the struct, with the credential
  already resolved to its value: nothing here names a key in some other
  store.

  ## Patterns

  `host[:port][/path]`. The host may be a `*.example.com` wildcard (matching
  subdomains, not the apex) and the path a prefix, with a trailing `*`
  matching the rest. A port pins the request's port; without one any port
  matches. Matching is case-insensitive on the host and ignores the query.

  When several patterns match one request, the **most specific** sets the
  header: an exact host beats a wildcard (whatever their paths), then a
  pinned port beats any port, then the longest literal path prefix wins,
  and declaration order breaks the rest. So defaults can be written first
  with overrides appended, which is the natural way to build the list, and
  a list of equally-specific rules behaves exactly as declaration order
  alone would.

  ## Schemes

  | `scheme` | fields | effect on a matched request |
  |---|---|---|
  | `:bearer` | `credential` (binary) | `Authorization: Bearer <credential>` replaces any `Authorization` header |
  | `:basic` | `credential` (`{username, password}`) | `Authorization: Basic base64(username:password)` |
  | `:api_key` | `header` (default `Authorization`), `prefix` (default `""`), `credential` (binary) | `<header>: <prefix><credential>` replaces that header |
  | `:custom` | `template` (`%{header => "text {{ KEY }}"}`), `credential` (`%{"KEY" => value}`) | each header rendered from its template; a `{{ KEY }}` with no value is left as written |
  | `:substitute` | `placeholder`, `credential` (binary) | every header *value* and the request target have each occurrence of `placeholder` replaced by `credential`; sets no header itself |
  | `:passthrough` | none | the request is forwarded untouched; under `deny` this is how a host is allowed |

  `:substitute` is the shape for a credential the agent addresses itself
  (an inference key the runtime sends as `x-api-key`, or as a bearer, in a
  placeholder it was handed, or a bot token in the URL path): the proxy
  does not need to know where the credential goes, only the placeholder. It
  reaches header values and the request target — so both `/bot<token>/send`
  and `?key=<token>` are brokered — but never a request body, which is one
  of the deviations from Agent Vault the README lists.

  A placeholder has to be *distinctive enough to be one*: at least four
  characters, holding a letter or digit, and carrying a boundary — `__` at
  either end, or a character outside `[A-Za-z0-9_]`. Substitution is a
  literal find-and-replace, so `"id"` would rewrite every `id` in every
  matching path and `"account_sid"` is a real field name that appears in
  URLs; the credential would land somewhere nobody chose, and nothing would
  raise. `Managoat.Broker.Injector.valid_placeholder?/1` is the check, and
  a host should call it when it builds a session so a bad rule fails where
  it is written. The proxy refuses a request matching such a rule either
  way.

  The credential replaces the placeholder in the target byte for byte: no
  percent-encoding is added and none is removed, because the proxy cannot
  know which URI component the placeholder sits in nor what the origin
  expects. A credential needing percent-encoding is declared already
  encoded. One holding a control character or a space is refused rather
  than written into the target, since it would split the request line.

  Several rules may match one request. The most specific one that sets a
  header is the one that does, by the precedence above; every matched
  `:substitute` rule applies, in declaration order. A `:passthrough` rule
  never displaces a rule that injects, however specific it is: it is how a
  host is allowed under `deny`, not a way to suppress injection.

  A rule the host could not put a credential in — `credential` left `nil`,
  or holding something other than the shape its scheme needs — has no
  header to build, and every request it matches is refused with `502`
  rather than sent without one. That is the shape a `Store` hands back when
  provisioning is incomplete, when a credential could not be decrypted, or
  when an OAuth grant was never connected, and `502` is what tells an agent
  to retry once it is provisioned rather than that it is not allowed. The
  two schemes that carry a placeholder instead of building a header are
  deliberately exempt: a `:substitute` rule with no credential forwards its
  placeholder as written, and a `:custom` template leaves a `{{ KEY }}` it
  has no value for alone.
  """

  @type scheme :: :bearer | :basic | :api_key | :custom | :substitute | :passthrough

  @type t :: %__MODULE__{
          name: String.t() | nil,
          pattern: String.t(),
          scheme: scheme(),
          credential: term(),
          header: String.t() | nil,
          prefix: String.t(),
          template: %{String.t() => String.t()},
          placeholder: String.t() | nil
        }

  @enforce_keys [:pattern, :scheme]
  defstruct [
    :name,
    :pattern,
    :scheme,
    :credential,
    :header,
    :placeholder,
    prefix: "",
    template: %{}
  ]
end
