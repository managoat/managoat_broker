# CLAUDE.md — Managoat.Broker

Read by Claude Code and other AI coding tools when a session starts in this
repository. Keep it accurate; stale guidance misleads every session that reads
it.

[README.md](README.md) is the normative description of *what this library
does* — the contract, the pieces, the semantics a consumer can rely on. Read it
first. This file is about working *in* the repository: the gate, the tests, the
release, and the traps.

## What this repository is

> An egress credential proxy for sandboxed agents: CONNECT and absolute-form
> forward proxy that attaches the real credential where the sandbox sent a
> placeholder, behind a session-store behaviour.

[`managoat_broker`](https://hex.pm/packages/managoat_broker) on hex,
`Managoat.Broker` in the code, Apache-2.0 throughout. It was extracted from
[Fountain](https://github.com/BinaryBourbon/fountain) under that project's ADR
0037 (component libraries, extracted umbrella-first under the `Managoat`
namespace) and graduated to this repository in BinaryBourbon/fountain#1345.
[NOTICE](NOTICE) records the lineage.

Fountain is now one consumer among others, pinned to a hex release like any
other dependency. The half of that which gets forgotten: **nothing here may
depend on Fountain, read its configuration, or assume its supervision tree.**
What the library needs from its host it takes as an argument, a behaviour, or a
configuration key with no default — so a consumer who names nothing gets an
error, not a silent default that happens to suit Fountain.

## Quick start

```bash
mise install        # Erlang/OTP 28.3 + Elixir 1.19.2, from .tool-versions
mix deps.get
mix test            # 7 test files
mix precommit       # the whole CI gate, locally
```

`.tool-versions` is asdf format, so `asdf install` works too. The pins are not
advisory: CI runs exactly these versions, and the dialyzer PLT cache is keyed
on them.

## Repo layout

```
lib/                    10 modules — README.md is the guide to them
test/                   7 test files, mirroring lib/
scripts/release.exs     the facts about a release, shared by the PR gate
                        and the publish workflow (no dependencies: it runs
                        before `mix deps.get` in both)
.github/workflows/      ci.yml           the gate
                        release-gate.yml does this PR need a version bump?
                        publish.yml      merging a bump ships it to hex
```

Test doubles this library ships for its *consumers* — they are part of the
package, not of this suite: `Managoat.Broker.Store.Memory`, the reference
in-memory `Store` implementation.

## The gate

`mix precommit` runs what `.github/workflows/ci.yml` runs, in the same order:

| Step | Why |
|---|---|
| `deps.unlock --unused` | an unused lockfile entry is a dependency someone removed and half-committed. Checked by diffing the lockfile, because the bare task rewrites it and exits 0 |
| `format --check-formatted` | |
| `compile --warnings-as-errors` | |
| `credo --strict` | config in `.credo.exs` |
| `dialyzer` | |
| `test --cover` | the coverage threshold gates here, not in a separate job |
| `hex.build` | what `mix hex.publish` will build. A dependency hex refuses — a git dep, a path dep — fails on the PR rather than on `main` |

`def cli` sets `preferred_envs: [precommit: :test]`, matching CI's job-level
`MIX_ENV: test`. Two steps override that back to `:dev` by shelling out, the
same override CI makes: dialyzer analyses the *shipped* code, so the test
environment would drag test-only dependencies into the analysis and into the
cached PLT, and `hex.build` builds the package as it will be published.

**The first `mix dialyzer` builds a PLT and takes minutes.** It lands in
`priv/plts/` — pinned there by `mix.exs` so CI can cache it across runs — and is
gitignored. Later runs take seconds.

Read the output rather than trusting the exit code, and confirm you reached
`N tests, 0 failures`.

## Coverage

`mix test --cover` gates at **97%**, configured in `mix.exs`.

What the suite measures on its own: the proxy end to end against a real Bandit
HTTPS origin, the CA, the injector, the HTTP slice and the in-memory store.

The threshold is a ratchet. Raise it as the suite grows; never lower it to turn
a red run green. If a change genuinely cannot be covered, say so in the PR — the
number is a claim about this library, and it is the one thing a consumer cannot
check for themselves.

## Test patterns

Every proxy test starts its own listener on port 0, its own in-memory store and
its own Bandit origin, so nothing is global and every module runs async.
`test/support/proxy_case.ex` is where that setup lives. `test/test_helper.exs`
is one `ExUnit.start()` line.

`agent_vault_parity_test.exs` is worth reading before changing behaviour: this
proxy replaced Infisical's Agent Vault behind the same interface, and that file
replays the upstream tests it stands in for *and* lists what was deliberately
not ported. README.md's "Deviations from Agent Vault" is the prose version.

## Releasing

The publish workflow ships whatever version lands on `main`, so **the version
bump is the release**. There is no tag to push and no button to remember.

1. Bump `@version` in `mix.exs`.
2. Add a `## [<version>]` heading to `CHANGELOG.md` saying what changed.
3. Merge. `publish.yml` publishes to hex and tags `v<version>`.

`release-gate.yml` runs `elixir scripts/release.exs guard` on every PR and fails
it when the PR changes what the package ships — `lib/`, `priv/`, or the
consumer-facing part of `mix.exs` — without a bump. Without that gate the change
sits on `main` unreleased, invisible until somebody wonders why the fix they
merged is not on hex.

The gate also front-loads what would otherwise fail the publish on `main`: a
version already on hex (hex never allows a version to be republished) and a
missing changelog heading.

The deliberate exception is the **`no-release`** label, which skips the gate.
It is for a change that touches those paths without altering what a consumer
gets. The PR that added this file is exactly that case: a `precommit` alias in
`mix.exs` is build tooling, and `scripts/release.exs` compares `mix.exs`
textually rather than semantically. Use the label rarely, and say why in the PR
body.

`scripts/release.exs state` prints the current facts as JSON, and is the same
code the gate and the publish workflow read, so the two can never disagree.

## Things NOT to do

- **Don't push directly to `main`.** Every change goes through a PR; `ci` and
  `release gate` are both required checks.

- **Don't take a dependency on the host application.** Not on Fountain, not on
  its configuration, not on its supervision tree. A configuration key this
  library reads should have no default when the right default is the host's
  business.

- **Don't lower the coverage threshold.** See above.

- **Don't promote `bandit`, `websock_adapter` or `jason` out of
  `only: :test`.** They are the test origin and its helpers, not the package's
  runtime dependencies; a consumer should not inherit a web server because this
  library tests against one.

- **Don't let a real credential reach a log or an error message.** The whole
  point of the injector is that the sandbox only ever holds a placeholder.

- **Don't describe unbuilt behaviour as existing.** In a moduledoc, the README
  or the changelog, mark what is not yet built as not yet built, and remove the
  caveat in the PR that builds it. A 2026-07 audit of the parent project found
  three mechanisms asserted as implemented that did not exist; everyone reading
  the docs concluded the system had properties it did not have.

- **Don't leave a `CHANGELOG.md` entry to the release.** Write it in the PR that
  makes the change, under the version that ships it.

## Where the wider context lives

Architecturally significant decisions from before the split are ADRs in
Fountain's `decisions/` directory; 0037 is the one that created this repository.
This library is small enough that its own design rationale lives where it
applies — in moduledocs and in README.md — rather than in a decision log of its
own. If a choice here needs more than a moduledoc paragraph, that is the signal
to start one.

[CONTRIBUTING.md](CONTRIBUTING.md) covers licensing, the DCO sign-off, and what
a PR is expected to carry.
