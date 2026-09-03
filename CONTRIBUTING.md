# Contributing to Managoat.Broker

Start with [CLAUDE.md](CLAUDE.md): the gate, the test patterns, the release
flow and the traps. [README.md](README.md) is the contract this library owes
its consumers.

## Licensing of contributions

This library is Apache-2.0, inbound and outbound. **You contribute under the
Apache License 2.0**, and that is what it is distributed under. There is no
separate document to sign and no CLA bot; opening a pull request is the grant.

You keep the copyright in your work. This is a license, not an assignment, and
Apache-2.0 does not restrict you, so you keep the full right to reuse your own
contribution anywhere else, including in proprietary code of your own.

One thing to know, stated plainly rather than left to be discovered: Apache-2.0
permits relicensing, and this library was extracted from
[Fountain](https://github.com/BinaryBourbon/fountain), which is not licensed as
a single unit. A contribution here can therefore be redistributed by Fountain's
maintainer under the AGPL, under the Elastic License, or under a commercial
license. That is the same asymmetry a CLA creates, with less ceremony. If it is
not a trade you want to make, say so on the pull request; it is a reasonable
thing to object to.

## Sign your commits (DCO)

This project uses the [Developer Certificate of
Origin](https://developercertificate.org/) — a one-line assertion that you wrote
the patch, or otherwise have the right to submit it. Your sign-off also records
your agreement to the inbound terms above. Add it with `-s`:

```bash
git commit -s -m "fix: ..."
```

That appends a `Signed-off-by:` trailer built from your `user.name` and
`user.email`. Note that `git config format.signOff true` does **not** do this
for `git commit`; use `-s`, or install a `commit-msg` hook.

## Before you push

```bash
mix precommit
```

That is the CI gate, in CI's order: the unused-dependency check, format,
compile with warnings as errors, `credo --strict`, dialyzer, the tests with
coverage, and the hex package build. Read the output rather than trusting the
exit code, and confirm you reached `N tests, 0 failures`.

The first run builds a dialyzer PLT and takes minutes. Later runs take seconds.

## Does your change need a release?

Probably, if it touches `lib/`. The publish workflow ships whatever
version lands on `main`, so the version bump *is* the release:

1. Bump `@version` in `mix.exs`.
2. Add a `## [<version>]` heading to `CHANGELOG.md` describing the change.

The `release gate` check enforces this on the PR, so it is caught during review
rather than after. `elixir scripts/release.exs guard origin/main` runs the same
check locally.

Versions follow [SemVer](https://semver.org/), and pre-1.0 a minor bump may
include breaking changes and says so. A version is never republished — hex
refuses it — so a bad release is fixed by another release.

For a change that touches those paths without altering what a consumer gets,
apply the **`no-release`** label and say why in the PR body.

## Pull requests

Every change goes through a pull request, and both checks — `ci` and
`release gate` — must pass. Nothing is pushed to `main` directly, and nothing is
published from a laptop.

A good PR body says what changed and why, and names the failure mode it
prevents when there is one. The commit history in this repository is written
that way; match it.
