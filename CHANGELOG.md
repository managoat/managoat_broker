# Changelog

All notable changes to `managoat_broker` are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Pre-1.0, a minor bump (`0.x` to `0.y`) may
include breaking changes and says so; patch releases are always safe to take.

Merging a version bump to `main` publishes it to hex; a PR that changes what
the package ships without a bump fails the release gate.

## [Unreleased]

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
