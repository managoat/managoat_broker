# Managoat.Broker

An egress credential proxy for sandboxed agents. The sandbox holds a
**placeholder** where a credential used to be, plus a proxy address with a
session token in it. Every outbound HTTP request goes through this proxy,
which looks the token up in a session store the host implements, gets back
the rules the host prepared for that session, and attaches the real
credential to each request that matches one. The agent process never holds
the credential; the proxy is the only host it may reach, so a placeholder
is worthless off the box.

```elixir
# The host's supervision tree:
children = [
  {Managoat.Broker,
   port: 14322,
   store: MyApp.BrokerSessions,        # a Managoat.Broker.Store
   ca_seed: MyApp.broker_ca_seed(),    # 32 bytes, the same on every replica
   allow_private_upstreams: false}
]

# The sandbox's environment, prepared by the host:
#   HTTPS_PROXY=http://<token>:<label>@broker.example.com:14322
#   GITHUB_TOKEN=__github_token__
# and the root from Managoat.Broker.ca_pem/0 in its trust store.
```

## What the proxy does

One plaintext HTTP listener (TLS toward the sandbox, if any, is the
ingress's job) speaking the two things a forward proxy speaks:

- **`CONNECT host:443`** for HTTPS. The proxy opens the upstream TLS
  connection first (an unreachable or untrusted origin is a `502` before any
  tunnel exists), answers `200`, then completes a TLS handshake with the
  *sandbox* using a leaf certificate for that host signed by the listener's
  own CA. Inside the tunnel it reads each request head, rewrites the headers
  per the session's rules, and forwards head and body to the origin. Bytes
  coming back are relayed untouched, so a streaming model reply streams;
  they are also framed, alongside the relay rather than in front of it, so
  each request's event can say what status it got and how long it took. Keep-alive works; every request on the tunnel is rewritten. A
  WebSocket upgrade is injected like any other request, after which the
  tunnel is a byte pipe.
- **Absolute-form requests** (`GET http://host/path`) for plain HTTP, one
  request per connection.

Either form may name an IPv6 literal, bracketed: `CONNECT [::1]:8443` and
`GET http://[::1]:8080/x`. Names are resolved over A *and* AAAA, and the
vetted addresses are dialed IPv4 first — every host that worked before
takes the address it took before, and IPv6 is a path for hosts that
previously had none. A leaf for a literal carries an `iPAddress` SAN
rather than a `dNSName` one, so it validates as a client verifying an
address expects.

The client authenticates with `Proxy-Authorization: Basic
base64(token:label)`, which is what an HTTP client sends for a proxy URL
with userinfo. The token is looked up once per client connection (the unit
a sandbox's HTTP client pools on); `proxy-authorization` never reaches the
origin. A missing, unknown or expired token is `407`.

Two guards protect the operator's network and the tenant's intent:

- **SSRF.** An origin that resolves into a private, loopback, link-local
  (including the cloud metadata address), CGNAT, unique-local, multicast or
  unspecified address is refused with `403` before any connection, in both
  address families, and the dial goes to a vetted address rather than the
  name, so a rebinding DNS answer between check and dial changes nothing.
  **Every** answer is vetted and one blocked answer refuses the host, so
  the decision never depends on resolver ordering. The IPv6 forms that
  embed an IPv4 address — `::ffff:`, `::`, `2002:` and `64:ff9b::` — are
  decoded and judged by the IPv4 policy, since each is otherwise a spelling
  of a blocked address that a range check would call public.
  `allow_private_upstreams: true` turns the guard off for a test rig whose
  origins are on localhost.
- **`deny`.** A session whose `unmatched_host_policy` is `:deny` refuses a
  host no rule names at `CONNECT`, before a tunnel or handshake exists, and
  refuses a request no rule matches inside a tunnel with `403`. That is how
  an allowlist is enforced: one `:passthrough` rule per allowed host.

## The `Store` behaviour

```elixir
@callback lookup(token :: binary()) :: {:ok, Managoat.Broker.Session.t()} | :error
```

That is all the proxy needs at request time: the raw token in, a session
with its rules (credentials already resolved) out. Creating, releasing and
sweeping sessions are the host's business; they touch its tables and its
key hierarchy, and the proxy never needs any of it. Hashing the token
before storing it is the host's choice inside `lookup/1`; the library
passes the raw token from the header.

A store with several instances (one per listener in a test) implements
`lookup/2` instead and is configured as `store: {Module, instance}`.
`Managoat.Broker.Store.Memory` is the reference store, an `Agent` holding a
map, for the library's tests and for a consumer without a database.

A `Managoat.Broker.Session` has `rules`, `unmatched_host_policy`
(`:passthrough` or `:deny`), `expires_at` and an opaque `meta` map the host
fills for its own logging. A `Managoat.Broker.Rule` has a `pattern`
(`host[:port][/path]`, wildcards allowed; an IPv6 literal is bracketed,
`[::1]` or `[::1]:8443`, since otherwise there is no telling which colon
is the port separator), a `scheme` and the fields the scheme needs:

| `scheme` | fields | effect on a matched request |
|---|---|---|
| `:bearer` | `credential` | `Authorization: Bearer <credential>` replaces any `Authorization` |
| `:basic` | `credential` as `{username, password}` | `Authorization: Basic base64(username:password)` |
| `:api_key` | `header` (default `Authorization`), `prefix`, `credential` | `<header>: <prefix><credential>` |
| `:custom` | `template` (`%{header => "text {{ KEY }}"}`), `credential` (`%{"KEY" => value}`) | each header rendered from its template |
| `:substitute` | `placeholder`, `credential` | every header value **and the request target** have the placeholder replaced by the credential |
| `:passthrough` | none | forwarded untouched; under `deny`, how a host is allowed |

The first matched rule that sets a header does; every matched
`:substitute` rule applies, in rule order, to the header values and to the
request target. A credential goes into the target byte for byte — nothing
is percent-encoded on the way in, because the proxy cannot know which URI
component a placeholder sits in nor what the origin expects, and the
canonical case says so: a bot token is `<digits>:<rest>` in a path
segment, where `:` is legal unencoded and `%3A` is a different URL. A
credential holding a control character or a space would split the request
line, so it is refused with `403` rather than written into a target.

A rule the host could not put a credential in — `credential` left `nil`, or
holding something other than the shape its scheme needs — has no header to
build. Every request it matches is refused with **`502`**, carrying
`error: :credential_missing` on the request event, rather than being sent
without the header: the broker failed to obtain a credential, which is not
the agent doing anything wrong, and `502` is what tells it to retry once
the credential is provisioned. `403` would say it is not allowed, which is
a different and misleading thing. Inside a tunnel the request is refused
without ending the tunnel, unless the refused request left a body behind it
in the stream. `:substitute` and an unfilled `{{ KEY }}` are the exceptions
described above: a placeholder the origin can see is the clearer failure
there.

A placeholder must be distinctive enough to be one: four characters or
more, holding a letter or digit, and carrying a boundary — `__` at either
end, or a character outside `[A-Za-z0-9_]`. Substitution is a literal
find-and-replace, so `id` would rewrite every `id` in a path and
`account_sid` is a real field name that appears in URLs.
`Managoat.Broker.Injector.valid_placeholder?/1` is the check; call it when
building a session, so a bad rule fails where it is written rather than on
every request it would have matched.

Rules match against the target the client sent, and telemetry is derived
from that same original, so a placeholder in a path is logged as the
placeholder and one in a query is not logged at all.

## The child spec

`{Managoat.Broker, port: 14322, store: Module, ca_seed: <32 bytes>,
allow_private_upstreams: false}`. Every option but the last is required,
and a missing one raises at start naming the option. Optional:
`upstream_ssl_options` (merged over the `:ssl` options the proxy dials
origins with; a test origin's `cacerts`) and `name` (default
`Managoat.Broker`, for several listeners in one VM). There is no
configuration module reading an otp_app: the listener is started by the
host with values the host computed at boot, and a library that is not
started serves nothing.

Once up: `Managoat.Broker.port/1`, `running?/1` and `ca_pem/1`.

## The CA

A brokered sandbox trusts one root, and the proxy presents a leaf for each
host the sandbox `CONNECT`s to, signed by that root. Every replica of the
host must present leaves the sandbox trusts, whichever one the ingress
hands a connection to, and a sandbox that survived a restart must still
trust what a fresh replica signs. So the root is not generated and stored:
it is **derived** from the 32-byte `ca_seed` with HKDF-SHA256, reduced into
P-256's scalar field, and the certificate's subject, serial and validity
are fixed, so every replica computes the same key, subject and serial from
the same seed. Rotating the seed rotates the CA; nothing else does.

The root's self-signature bytes vary per derivation, because ECDSA signing
is randomised, so two replicas' PEMs differ byte for byte. That is
harmless: a client matches a trust anchor by subject and public key and
never verifies a root's own signature. `ca_test.exs` proves a leaf signed
after a re-derivation chains to the first root.

The seed is the host's to derive, and it must not be a key the host uses
for anything else: derive it from a master key with a fixed info string,
so the CA key is never the storage key. Leaves live thirty days, are cached
per host in an ETS table the listener owns, and are re-signed after
twenty-nine.

## Telemetry

Every request the proxy decides about emits `[:managoat, :broker,
:request]` with the measurements `%{count: 1, duration: <native units>}`
and the metadata `method`, `host`, `path`, `outcome` (`:injected`,
`:passthrough` or `:denied`), `rule` (the matched rule's name, or nil),
`status`, `error` and `meta` (the session's, unchanged). Never a header,
never a body. The host attaches a handler and writes its log line with
whatever `meta` carries; the library logs only refusals, which have no
session to attribute.

**The event is terminal**: one per request, emitted when the request is
over rather than when it starts.

- For an upstream response, it fires once the response body has completed
  or failed. `status` is the status the origin sent; `duration` is
  monotonic, in native time units (`System.convert_time_unit/3` turns it
  into milliseconds), and covers the whole request through the end of the
  response body — not time to first byte.
- For a refusal the proxy makes itself, it fires immediately, with the
  status the proxy sent (`403`).
- `error` is nil when the request completed. Otherwise it is one of
  `:upstream_send_failed`, `:upstream_read_failed`, `:malformed_response`,
  `:upstream_closed` or `:client_closed`. A response whose head arrived and
  whose body then failed carries both its `status` and its `error`.

A consequence worth planning for: **a long-lived request is not recorded
until it ends**, so a streaming reply appears in a host's audit log when
the stream finishes. That matches Agent Vault's total-duration semantics
and avoids a second event and a row-update protocol. If immediate
visibility for long-lived requests is ever needed, that is correlated
start/stop events, not more meaning packed into this one.

Framing never touches the relay. Every byte from the origin is written to
the sandbox the instant it arrives, and only then shown to the framer, so a
streaming reply streams exactly as it did before responses were parsed and
a framing failure costs telemetry rather than the response.

`path` is the URL path and nothing else. A query string never appears in
it, on either request path, because a query can already hold a credential
this proxy never brokered — a signed URL is one in itself, and `?key=` is
a shape clients use. The origin receives the request target unchanged;
only the event is narrowed. This is Agent Vault's contract too: its
request log recorded `r.URL.Path`. A `CONNECT` names an authority rather
than a path, and is reported as it was sent.

## Deviations from Agent Vault

This proxy replaced Infisical's Agent Vault behind the same interface. The
parity suite (`test/managoat/broker/agent_vault_parity_test.exs`) replays
the upstream tests it stands in for and lists what was not ported.

Each of these is a decision rather than a backlog item. Agent Vault is
deleted from the cluster and from Fountain's codebase, so the A/B that
settled the last round — the same request against both proxies, compared
on the wire — no longer exists. A row reopened here has to be argued from
the upstream tests in the parity suite, from Agent Vault v0.39.1's source,
or from the protocol; it cannot be measured.

### Deliberate, and expected to stay that way

- **No auth-failure rate limiting on the proxy port.** Agent Vault had
  one, and **having it caused a production incident**: the limiter counted
  per source address, every sandbox behind one NAT egress shared an
  address, and one misconfigured client locked out unrelated tenants. Not
  having it is the fix, not the gap.

  The assumption that replaces it is operational, and a host has to hold
  up its end: **the listener is reachable only through the intended
  ingress or network boundary.** If that ever stops being true, the answer
  is not to restore the limiter as it was — it is to key one on something
  better than the peer address.

- **The label half of the proxy credential is not checked.** Agent Vault
  refused a valid token presented with another vault's name. Here the
  per-session token is random and is the whole binding, so checking the
  label would add no authority — there is nothing a wrong label could
  protect. The label exists only because some clients (git) refuse a proxy
  URL with a username and no password.

- **No WebSocket frame rewriting.** The upgrade request is injected like
  any other; the frames after it are piped as bytes. Rewriting them is
  possible without buffering a whole WebSocket, but it replaces a byte
  pipe with a protocol implementation that has to get masking,
  fragmentation, control-frame interleaving and negotiated compression
  right before a substitution is even correct. Nothing sends a credential
  inside a frame today. The simple byte pipe is worth keeping until
  something does.

### Deliberate for now, with a condition attached

- **Absolute-form (plain HTTP) is one request per connection.** The proxy
  adds `Connection: close` upstream and closes after the response; HTTPS
  tunnels keep-alive normally.

  Supporting client keep-alive is not just dropping that header:
  successive absolute-form requests on one proxy connection may name
  different origins, so auth and session reuse have to stay well-defined,
  and finding the response boundary safely needs the response framing that
  now exists. The traffic is apt and little else, and no consumer needs
  it. If one does, it gets its own issue and its own acceptance tests
  rather than riding along with something else.

- **Body caps are configurable, with Agent Vault's defaults.**
  `max_request_bytes` defaults to 1 GiB, matching Agent Vault's
  `DefaultMaxRequestBytes`; `max_response_bytes` defaults to `:infinity`,
  matching its `DefaultMaxResponseBytes` of 0. So a consumer that names
  neither gets Agent Vault's behaviour.

  A request whose declared `Content-Length` exceeds the cap is refused with
  `413` before the origin is told anything. A chunked body, which declares
  no length, is counted as it streams and the connection ends when it
  passes the cap — the origin already holds a partial body by then, so
  there is nothing honest left to say. The count includes chunk framing,
  which makes the cap very slightly conservative rather than parsing a body
  this proxy has no business reading.

  A response cap can only *end* a response, never prevent one: every byte
  reaches the sandbox before the framer sees it, which is what keeps a
  stream a stream. So an over-long response arrives up to roughly the cap
  and the connection is then torn down. Agent Vault ends the same way, by
  aborting mid-stream.

- **No body substitution.** The `:substitute` rule reaches header values
  and the request target — a placeholder in a path (`/bot<token>/send`) or
  a query (`?key=<token>`) is replaced on both request paths — but a
  request body is forwarded as bytes.

## Two operational traps a host must handle

Both were found in production with the previous broker and are about the
sandbox and the ingress, not the proxy, so this library cannot fix them.

- **`sudo` strips the proxy environment.** A sandbox that runs `sudo
  apt-get` loses `HTTPS_PROXY` and the rest, and the install fails against
  a closed network with an error naming apt, not the proxy. Provisioning
  has to keep the proxy variables across `sudo` (`Defaults env_keep` in a
  sudoers drop-in).
- **An unknown CA leaf, and a shared-NAT peer.** A sandbox that does not
  trust the root sees every brokered host fail TLS with an "unknown
  issuer" error the tool attributes to the origin. The root has to reach
  the operating system trust store (`update-ca-certificates`) and the
  toolchains that carry their own roots (`NODE_EXTRA_CA_CERTS` for Node,
  `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CARGO_HTTP_CAINFO` pointed at the
  full system bundle, `UV_NATIVE_TLS`) before anything else runs. The same
  incident's other half was a per-IP auth rate limiter at the vendor's
  proxy port tripping on many sandboxes behind one NAT address; this proxy
  has none, so nothing in front of it needs to allow for that.

## Licence

Apache-2.0. See `LICENSE`.
