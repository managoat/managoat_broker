# Changelog

All notable changes to `managoat_broker` are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Pre-1.0, a minor bump (`0.x` to `0.y`) may
include breaking changes and says so; patch releases are always safe to take.

Merging a version bump to `main` publishes it to hex; a PR that changes what
the package ships without a bump fails the release gate.

## [Unreleased]

## [0.9.0] - 2026-09-03

The leaf cache is bounded, and a host is validated before it can become a
cache key or a certificate subject. Closes #21.

### Fixed

- **The leaf certificate cache no longer grows without limit.** It held one
  signed leaf per distinct host ever tunnelled, refreshed after
  twenty-nine days but never removed, for the life of the listener. Its key
  is the host from a sandbox's own `CONNECT` line, so what it held was
  chosen by the sandbox: under `:passthrough` an agent browses wherever it
  likes, and a wildcard DNS record aimed at one address makes every
  `*.attacker.example` a distinct name that resolves, connects and is
  cached. Nothing dramatic — entries are small and signing is milliseconds
  — but unbounded growth driven by an untrusted input is the shape worth
  fixing before it matters.

  It now holds at most **`max_cached_leaves`** (default **1024**) and
  evicts the **least recently used**. A leaf is marked used on every hit,
  so a host still being visited keeps its leaf across evictions of others
  and a busy listener does not become a re-signing treadmill. Going over
  the cap refuses nothing: a host that fell off costs one ECDSA signature
  the next time it is seen, which is what the cache was saving in the first
  place.

### Added

- **`Managoat.Broker.HTTP.valid_host?/1`, enforced by `destination/1`.** A
  host from a request line reaches `:inet.getaddrs`, the TLS
  `server_name_indication`, the leaf cache's key and **the subject and SAN
  of a certificate this proxy signs** — a `/` ends the relative
  distinguished name a leaf's subject is built from, and an `@` reads as
  userinfo to anything that parses a URL out of the name again.

  So a host longer than 253 bytes, or empty, or beginning or ending with a
  dot, or holding a control character, whitespace or any of `@ / \ ? # %`
  is now **`400`**, on both request paths, before it is resolved, dialed,
  cached or signed. It is refused rather than sanitised: forwarding a name
  the client did not ask for is worse than refusing the one it did.

  This is Agent Vault's `brokercore.IsValidHost` less its DNS-name
  blocklist (`localhost`, `kubernetes.default`,
  `metadata.google.internal`, `instance-data`), which is deliberately not
  ported: the SSRF guard here works on the addresses a name *resolves to*,
  so it catches every name that reaches a blocked range rather than the
  four anyone thought to write down.

- **`max_cached_leaves`** on the listener, and
  `Managoat.Broker.Certs.cached_leaves/1` to see what the cache is holding.
  `Certs.new/2` takes the cap; `new/1` still means the default.

## [0.8.0] - 2026-09-03

A wall-clock bound on reading one request, which is what actually closes
the connection-occupancy hole 0.6.0 claimed the byte cap closed.

### Added

- **`request_read_timeout`**, defaulting to **five minutes**: the wall
  clock the proxy will spend reading one request, head and body, starting
  with that request's first byte. A read that would outlast it is cut
  short; where the origin has been told nothing yet the client gets `408`,
  and where the head has already been forwarded the connection ends
  without a reply, because the origin already holds a partial body — the
  same choice the request cap makes for a chunked body that passes it
  while streaming. Either way one terminal event, with
  `error: :request_timeout`. Closes #20.

  It is the only timeout here a host can name, and the reason is that it
  is the only one that can refuse a *valid* request: a large upload over a
  slow link is legitimate and slow. `:infinity` turns it off.

  The response side is deliberately outside it. A `git clone` or an SSE
  stream runs long on the way back, which is the traffic this proxy exists
  for, and the existing streaming tests show a long response is unaffected.
  WebSocket frames after an upgrade are outside it too: they are no longer
  a request being read.

### Fixed

- **A correction to 0.6.0.** That release's changelog said of the request
  byte cap: "bodies are read with a five-minute idle timeout per read, so
  an authenticated client sending one byte every four minutes held a
  connection open indefinitely. A byte cap bounds that; the idle timeout
  alone did not."

  That overstates what the byte cap does. `@idle_timeout` is per `recv`,
  so a client sending one byte every four minutes never trips it, and at
  that rate the default 1 GiB cap is reached in roughly **eight thousand
  years**. The cap bounds volume, not time; the connection-occupancy hole
  stayed open until this release. The availability argument for the byte
  cap stands on its own — a single request is not allowed to be
  arbitrarily large — but it was never the bound on how long one could
  take.

### Decided, and unchanged

- **The gap between requests and the gap between body chunks stay the same
  300s.** Agent Vault used 2 minutes and 60 seconds. Splitting them would
  change *when* a stalled request dies, not whether, now that a deadline
  bounds the whole read; a connection held open between requests is doing
  what a proxy connection is for.

- **No upstream response-header timeout.** Agent Vault had one at 5
  minutes. A stalled origin is bounded here only indirectly on the
  absolute-form path and not at all inside a tunnel, where the relay waits
  on origin bytes with no deadline; closing that needs a per-request timer
  in the relay rather than a timeout argument, and it is the response side,
  where long is legitimate. Recorded in README.md's deviations rather than
  built. Nothing has needed it: a stalled origin costs a socket, and the
  sandbox's own client gives up on its own.

## [0.7.0] - 2026-09-03

Rule matching is by specificity rather than declaration order. A host whose
rules are all equally specific sees no change; one that wrote defaults with
overrides appended was silently getting the default, and now gets the
override.

### Changed

- **The most specific matched rule sets the header, not the first
  declared.** Four ordered tiers, matching Agent Vault's `MatchService`
  (internal/broker/broker.go): an exact host beats a `*.` wildcard even
  when the wildcard carries the longer path; within a host tier a pinned
  port beats any port; within a host and port tier the longest literal
  path prefix wins; and declaration order breaks what is left — so a list
  of equally-specific rules resolves exactly as it did before.

  Defaults first with overrides appended is the natural way to build a
  rule list, and under declaration order the appended override lost. The
  failure was not an error but a wrong answer: the request went out with
  the *generic* credential and **succeeded**, and the event named the rule
  that had won, so the audit log looked fine too. The README documented
  the old rule, so this was a divergence from Agent Vault rather than a
  bug — but one that produced a wrong answer rather than no answer, and it
  was never recorded in the deviations list. Closes #19.

- **The request event's `rule` names the rule that actually set the
  header**, falling back to the first matched rule when none did. It named
  the first matched rule before, which after this change could name a rule
  that did nothing. Where a `:substitute` rule and a header rule both
  match, the event now names the header rule; the substitutions still
  apply.

### Decided, and unchanged

- **`:passthrough` never displaces a rule that injects**, however specific
  it is. It is how a host is allowed under `deny`, not a way to suppress
  injection: if an exact-host allowlist entry outranked a wildcard
  `:bearer`, a host would *stop* attaching the credential by allowlisting
  more precisely. A host that means "reach this untouched" says so by not
  writing a rule that injects. Pinned by a test under both policies.

- **Every matched `:substitute` rule still applies, in declaration
  order.** Scoring picks one rule to set the header and says nothing about
  the substitutions, because several placeholders can legitimately appear
  in one request.

## [0.6.2] - 2026-09-03

### Fixed

- **A matched rule with no usable credential is refused with `502`, not a
  crash.** `Injector.put_auth/2` was guarded on the credential's shape and
  had no fallback, so a `:bearer`, `:basic`, `:api_key` or `:custom` rule
  holding `nil` — or anything else the scheme cannot build a header from —
  raised `FunctionClauseError` inside the handler. The client got no
  response at all, no `[:managoat, :broker, :request]` event was emitted so
  the failure was invisible in the host's audit log, and inside a tunnel it
  killed the tunnel rather than the request.

  It now refuses, with the status and the reasoning Agent Vault's
  `ErrCredentialMissing` documents: the broker failed to obtain a
  credential, so an agent should retry once it is provisioned. `403` would
  say it is not allowed, which is a different and misleading thing. The
  event carries `status: 502` and `error: :credential_missing`, and the
  warning names the rule and the scheme and never the credential. Inside a
  tunnel the request is refused without ending the tunnel, unless the
  refused request left a body behind it in the stream — the proxy will not
  read a body it is refusing to forward, so the next head could not be
  found. It is the shape a `Store` hands back when provisioning is
  incomplete, when decryption failed, or when an OAuth grant was never
  connected (`ErrOAuthNotConnected`, `ErrOAuthRefreshFailed`).

  Unchanged, deliberately: a `:substitute` rule with a valid placeholder
  and no credential still forwards the placeholder as written, and a
  `:custom` template still leaves an unfilled `{{ KEY }}` alone. There the
  origin refusing a visible placeholder is the clearer failure. Closes #18.

## [0.6.1] - 2026-09-03

### Added

- `Managoat.Broker.Proxy.addresses/1`, the other half of the guard that
  `blocked/1` was already the public face of: every address a host
  resolves to, in the order the proxy would dial them.
  `blocked(addresses(host))` empty is the whole check.

  It was private, which left the A∪AAAA union — added in 0.4.0 — with no
  direct test. If the two lookups had been transposed the union would have
  been identical and only the dial preference would have changed, silently
  and on every host. Closes #14.

## [0.6.0] - 2026-09-03

Body size limits. Closes #12, and with it the last real Agent Vault parity
gap (row 8a of #5).

### Added

- **`max_request_bytes`**, defaulting to **1 GiB** — Agent Vault
  v0.39.1's `DefaultMaxRequestBytes`. A request whose declared
  `Content-Length` exceeds it is refused with `413` before the origin is
  told anything, on both request paths. A chunked body declares no length,
  so it is counted as it streams and the connection ends when it passes
  the cap; by then the origin holds a partial body, so there is nothing
  honest left to say to the client. The count includes chunk framing,
  which makes the cap very slightly conservative — deliberately, since the
  alternative is parsing a body this proxy has no business reading.

  #5 noted the memory-exhaustion rationale is weaker here, since request
  bodies stream rather than materialising. The argument that survives is
  availability, and it is concrete: bodies are read with a five-minute
  idle timeout per read, so an authenticated client sending one byte every
  four minutes held a connection open indefinitely. A byte cap bounds
  that; the idle timeout alone did not.

- **`max_response_bytes`**, defaulting to **`:infinity`** — Agent Vault's
  `DefaultMaxResponseBytes` of 0. Not a parity gap, so it is opt-in and
  the default changes nothing.

  A cap here can only *end* a response, never prevent one: every byte
  reaches the sandbox before the framer sees it, which is what keeps a
  stream a stream. An over-long response therefore arrives up to roughly
  the cap and the connection is then torn down. Agent Vault ends the same
  way, aborting mid-stream.

- Two error atoms on `[:managoat, :broker, :request]`:
  `:request_too_large` and `:response_too_large`.

- `Managoat.Broker.Response.new/1` takes the response cap, and
  `halted?/1` says whether framing stopped because one was passed.

### Notes

Both options default rather than being required, a deliberate exception to
"a configuration key should have no default when the right default is the
host's business": a body cap's right default is not host-specific, and
requiring one would break every consumer on upgrade. **A consumer that
names neither gets Agent Vault's behaviour**, which is the point of
choosing its numbers.

## [0.5.0] - 2026-09-03

### Changed

- **`:substitute` placeholders are validated, and a rule with an unusable
  one is refused.** A placeholder must be at least four characters, hold a
  letter or digit, and carry a boundary — `__` at either end, or a
  character outside `[A-Za-z0-9_]`. A matched rule that fails this gets
  `403` and a `:warning` naming the rule, never the credential. Closes #11.

  Substitution is a literal find-and-replace, and 0.2.0 extended it from
  header values to the request target — which is what makes this worth
  enforcing rather than documenting. A rule declaring `placeholder: "id"`
  silently rewrote every `id` in every matching path; the credential landed
  somewhere nobody chose and nothing raised. Agent Vault validates for the
  same reason, its comment naming `account_sid` as the case: a real field
  name that legitimately appears in URL path segments.

  **This can refuse traffic that previously succeeded**, which is the
  point. A host on a short placeholder should rename it before upgrading.
  `Managoat.Broker.Injector.valid_placeholder?/1` is public so a session
  can be checked where it is built rather than on every request it matches.

  An empty placeholder used to be ignored silently, leaving the request
  untouched; it is now refused like any other unusable one.

- A `:substitute` rule with a valid placeholder and no credential still
  forwards the placeholder as written, unchanged from before. That is the
  same choice `:custom` makes for an unfilled `{{ KEY }}`: the origin
  refuses a placeholder, which is a clearer failure than a credential sent
  empty.

### Added

- `Managoat.Broker.Injector.valid_placeholder?/1`.

## [0.4.0] - 2026-09-03

IPv6 upstreams. Row 3 of #5. This is a minor bump because the SSRF guard's
policy widens and `Managoat.Broker.Injector` gains a pattern form; nothing
that worked before behaves differently.

### Added

- **IPv6 upstreams.** Names resolve over A *and* AAAA rather than A alone,
  so an IPv6-only origin connects instead of getting a hard `502`. Both
  request paths may also name an IPv6 literal, bracketed —
  `CONNECT [::1]:8443` and `GET http://[::1]:8080/x` — since without
  brackets there is no telling which colon separates the port. An
  unbracketed literal is a `400`, not a guess about where the request goes.

- Rule patterns take a bracketed IPv6 literal, with or without a port:
  `[::1]`, `[::1]:8443`, `[::1]/api`. A bare literal is not a pattern; its
  first colon reads as the port separator, so it matches nothing rather
  than matching somewhere else by accident.

  A pattern that is an address is matched by **value**, not by spelling, on
  both sides: `[::1]`, `[::0001]` and `[0:0:0:0:0:0:0:1]` are one pattern,
  and a client naming any of them matches any of them. Matching the text
  would have failed silently — no rule matched, so no credential attached
  and no error — which is the worst way for a rule to be wrong. A name is
  still matched case-insensitively.

- A leaf certificate for a literal host carries an `iPAddress` SAN in the
  four or sixteen octets RFC 5280 asks for, rather than a `dNSName` of the
  address's text. A client verifying an address looks for exactly that, so
  the previous behaviour would have failed verification with a message
  about the name — a confusing way to learn the proxy issued the wrong kind
  of certificate.

- `Managoat.Broker.Proxy.blocked/1`, the vetting decision as a named
  function: which of a set of resolved addresses the proxy must not dial.

### Changed

- **The SSRF guard covers IPv6**, and had to before AAAA resolution could
  be added at all: `private?/1` matched four-element tuples only, so
  resolving AAAA without extending it would have handed a sandbox every
  private range back through a second address family, `::ffff:169.254.
  169.254` included.

  Refused are the unspecified address, loopback, `fe80::/10`, the
  deprecated `fec0::/10`, `fc00::/7`, `ff00::/8`, `2001:db8::/32` and
  `100::/64`. The four forms that *embed* an IPv4 address — IPv4-mapped
  (`::ffff:`), IPv4-compatible (`::`), 6to4 (`2002:`) and the NAT64
  well-known prefix (`64:ff9b::`) — are decoded and judged by the IPv4
  policy, because each is otherwise a spelling of a blocked address that a
  range check alone would call public. All four reach the cloud metadata
  service.

- **Every resolved address is vetted before any dial, and one blocked
  answer refuses the host.** Checking only the address about to be dialed
  would make the refusal depend on resolver ordering, so a name with one
  public and one private answer would be refused or allowed by luck. This
  is the conservative rule Agent Vault used.

- The dial then walks the vetted addresses in order rather than taking the
  first, so a host whose first address will not take a connection still
  reaches one that will. The order is IPv4 then IPv6: every host that
  worked before takes the address it took before, and IPv6 is a path for
  hosts that previously had none.

- An origin named by address gets no SNI: RFC 6066 has no name to put
  there and forbids sending one, so the option is **omitted** rather than
  set to `:disable`. `:disable` would have been the obvious spelling and is
  a hostname-verification bypass — `:ssl` then checks nothing, and accepts
  a certificate naming any address at all. Omitted, `:ssl` falls back to
  the connect call's own `Host` argument, which is the vetted address, and
  matches the certificate's `iPAddress` SAN against it.

### Notes

The `:ipv6` tests bind a listener on `::1`, and `test_helper.exs` excludes
that tag on a host with no IPv6 loopback — a real configuration rather than
a broken checkout. Everywhere else they run.

## [0.3.0] - 2026-09-03

This minor bump changes the shape and the timing of the request event; see
Changed before upgrading. Row 2 of #5.

### Added

- Responses are framed, so `[:managoat, :broker, :request]` can say how a
  request ended. The event gains `status` and `error` in its metadata and a
  monotonic `duration` in its measurements, in native time units beside
  `count` (`System.convert_time_unit/3` turns it into milliseconds).
  Fountain's `broker_requests` table has had `status`, `latency_ms` and
  `error` nullable and unwritten, waiting for exactly this.

  `error` is nil on a request that completed, and otherwise one of five
  documented reasons: `:upstream_send_failed`, `:upstream_read_failed`,
  `:malformed_response`, `:upstream_closed` or `:client_closed`. A response
  whose head arrived and whose body then failed carries both its status and
  its error.

- `Managoat.Broker.Response`, the framer. It handles informational `1xx`
  before a final response, `HEAD`, `204`, `304`, fixed-length, chunked with
  trailers, and close-delimited responses, correlates keep-alive and
  pipelined responses to their requests in order, and hands a `101` back to
  the existing byte pipe so WebSocket behaviour is unchanged.

- `Managoat.Broker.HTTP.parse_response/1` and `response_framing/3`, the
  response-side mirror of the request parsing already there, and a
  `:until_close` framing for a response delimited only by the connection
  ending.

### Changed

- **The request event is now terminal, and fires later.** It used to be
  emitted before the request was even sent upstream, which is why it could
  never carry a status: a telemetry event is a one-shot value. There is
  still exactly one event per request, on every terminal path, but an
  upstream response now emits when its body completes or fails, and a
  refusal the proxy makes itself emits immediately with the status the
  proxy sent (`403`).

  The consequence to plan for: **a long-lived request is not recorded until
  it ends**, so a streaming reply reaches a host's audit log when the
  stream finishes rather than when it starts. That is Agent Vault's
  total-duration semantics — it emitted after `io.Copy` returned — and it
  avoids a second event plus a row-update protocol. If immediate visibility
  for long-lived requests is ever needed, that is correlated start/stop
  events, not two meanings in one.

- Measurements are `%{count: 1, duration: <native>}` rather than
  `%{count: 1}`. A handler matching `%{count: 1}` still matches.

### Notes

Framing never gets in the relay's way. Every byte from the origin is
written to the sandbox the instant it arrives and only then shown to the
framer, so a streaming reply streams exactly as it did before responses
were parsed, response bodies are never accumulated, and a framing failure
costs telemetry rather than the response.

## [0.2.0] - 2026-09-03

This minor bump carries one breaking change to a public function; see
Changed. Everything else is additive.

### Added

- `:substitute` rules now reach the **request target** as well as header
  values, so a credential a client puts in the URL is brokered: a
  placeholder in a path (`/bot<token>/sendMessage`, the bot-API shape Agent
  Vault shipped a `telegram` preset for) or in a query (`?key=<token>`) is
  replaced with the real credential, on both the CONNECT and the
  absolute-form request path. A tenant declares its placeholder and nothing
  more; it does not have to tell the proxy where the client put it. Row 1
  of #5.

  The credential replaces the placeholder byte for byte: nothing is
  percent-encoded on the way in and nothing is decoded. The proxy cannot
  know which URI component a placeholder sits in nor what encoding the
  origin expects, and the canonical case settles it — a bot token is
  `<digits>:<rest>` in a path segment, where `:` is legal unencoded and
  `%3A` would be a different URL. A credential needing percent-encoding is
  declared already encoded.

  A credential that cannot be written where its placeholder sits is refused
  with `403` rather than written out or silently encoded. The two surfaces
  do not have the same rule: a **target** refuses a control character or a
  space, either of which would end the request line and start a second
  request; a **header value** refuses CR or LF, which would end the field
  and start another one, but not a space, which is ordinary there and fills
  a signature header. Each rule is checked only against the surfaces its
  placeholder actually reaches. The refusal is `{:error,
  {:unsafe_credential, rule_name, surface}}`, and logs the rule's name and
  the surface at `:warning` — never the credential.

  The header half closes a gap that predates this change: `:substitute`
  already reached header values, with no CRLF guard at all.

  Rules still match against the target the client sent, and telemetry is
  still derived from that original, so a placeholder in a path is logged as
  the placeholder and one in a query is not logged at all.

### Changed

- **Breaking:** `Managoat.Broker.Injector.inject/5` returns `{:ok, headers,
  target, rule_name}` rather than `{:ok, headers, rule_name}`, and may
  return `{:error, {:unsafe_credential, rule_name, surface}}` beside
  `{:error, :denied}`. Injection now rewrites the request target, so the target to
  forward is part of its result. Callers other than
  `Managoat.Broker.Proxy` are not expected — the function is public because
  the proxy is thin over it — but a consumer calling it directly has to
  take the extra element.

## [0.1.3] - 2026-09-03

### Fixed

- The `path` on `[:managoat, :broker, :request]` is now the URL path alone,
  on both request paths. An origin-form request inside a `CONNECT` tunnel
  was logged with its whole target, query string included, while an
  absolute-form plain-HTTP request was not; `GET /x?token=... HTTP/1.1`
  down a tunnel therefore put the query into a host's audit log. A query
  can hold a credential this proxy never brokered — a signed URL is one in
  itself — so the no-credential-in-logs invariant cannot depend on what the
  proxy substitutes. Queries and fragments are now dropped from the event
  on both paths; the origin still receives the request target byte for
  byte. This matches Agent Vault, whose request log recorded `r.URL.Path`.
  Row 0 of #5.

## [0.1.2] - 2026-09-03

### Fixed

- A `407` no longer closes the connection. The challenge is an invitation to
  retry, and a client that negotiates proxy authentication rather than
  sending it preemptively retries on the same socket: it sent its first
  request bare in order to learn the scheme. Closing made that retry land on
  a dead socket, which is what `http.proxyAuthMethod=anyauth` — git's
  default — does, and it broke every brokered `git clone` when Fountain
  moved production onto this library (BinaryBourbon/fountain#1493). The
  connection is now held open for the retry and advertises
  `Proxy-Connection: Keep-Alive`, bounded by three attempts and the existing
  head timeout, and only when the refused request has no body.
- A request with no `Proxy-Authorization` logs at `:debug` instead of
  `:info`. It is the first half of a negotiation and the shape of every
  credential-less liveness probe, so at `:info` a 30-second probe wrote
  ~2,880 lines a day and buried the refusals that mean something. A token
  that is unknown or expired still logs at `:info`.

### Added

- `[:managoat, :broker, :connect]`, one event per connection the proxy
  decides about, with the metadata `host`, `port`, `outcome` (`:ok`,
  `:upstream_failed`, `:denied` or `:unauthenticated`) and `meta`. The `502`
  path emitted nothing before, so there was no series behind "how much of
  this broker's egress is failing" — and because the event covers every
  path, that question is a ratio rather than a count with no denominator.

## [0.1.1] - 2026-09-03

### Changed

- Raised the test coverage gate from 85% to 97% after adding behavioral
  coverage for malformed HTTP, abandoned clients, partial request bodies,
  unreachable plain-HTTP origins, listener defaults and incomplete
  substitution rules.

## [0.1.0] - 2026-09-02

### Added

- Extracted from Fountain (BinaryBourbon/fountain#1367).
