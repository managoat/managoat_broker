# Changelog

All notable changes to `managoat_broker` are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[SemVer](https://semver.org/). Pre-1.0, a minor bump (`0.x` to `0.y`) may
include breaking changes and says so; patch releases are always safe to take.

Merging a version bump to `main` publishes it to hex; a PR that changes what
the package ships without a bump fails the release gate.

## [Unreleased]

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
