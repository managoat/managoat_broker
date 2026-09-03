# Run from this directory the library has no config at all (mix.exs sets no
# config_path on purpose) and needs none: every proxy test starts its own
# listener on port 0, its own in-memory store and its own Bandit origin, so
# nothing here is global and the modules run async.

# Tests tagged `:ipv6` bind a listener on `::1`. A runner without an IPv6
# loopback is a real configuration rather than a broken checkout, so they
# are excluded there instead of failing — and only there, so a machine that
# has IPv6 always runs them.
exclude = if Managoat.Broker.ProxyCase.ipv6_loopback?(), do: [], else: [:ipv6]

if exclude != [] do
  IO.puts("no IPv6 loopback on this host: excluding the :ipv6 tests")
end

ExUnit.start(exclude: exclude)
