defmodule Managoat.Broker.Certs do
  @moduledoc """
  One listener's certificates: the derived root, and the per-host leaves
  the proxy presents, cached in an ETS table.

  Signing a leaf is a few milliseconds of ECDSA; a sandbox opens a new
  tunnel per connection, so the same host comes back many times. Leaves
  live thirty days and are re-signed after twenty-nine.

  The table is created by the listener's supervisor (`Managoat.Broker`), so
  it lives exactly as long as the listener, and handed to every connection
  handler as an option. Public, so the handlers read and insert without a
  round trip through a process.

  ## The cache is bounded

  Its key is the host from a sandbox's own `CONNECT` line, so what it holds
  is chosen by the sandbox rather than by the host application. Under
  `:passthrough` an agent browses wherever it likes, and a wildcard DNS
  record aimed at one address makes every `*.attacker.example` a distinct
  name that resolves, connects, and would otherwise be cached forever.

  So the table holds at most `max_leaves` of them — 1024 unless the
  listener says otherwise — and the **least recently used** goes first. A
  host still being visited keeps its leaf across evictions of others, so a
  busy listener does not turn into a re-signing treadmill; a host that
  falls off the end costs one ECDSA signature the next time it is seen,
  which is what the cache was saving in the first place.

  1024 leaves is a megabyte or two, far above what an agent's browsing
  produces in one listener's lifetime and far below what would be worth
  noticing. It is a constant rather than a required option because passing
  it cannot refuse anything: over the cap the proxy re-signs, it does not
  fail.

  The proxy validates a host before it reaches here (`Managoat.Broker.HTTP.
  valid_host?/1`), which is what keeps a name that would break a
  certificate's subject out of one. The cap is the bound that does not
  depend on the caller having done that.
  """

  alias Managoat.Broker.CA

  @refresh_after_seconds 29 * 86_400
  @default_max_leaves 1024

  # The keys in the table that are not leaves. `:ets.info/2` counts every
  # object, so the leaf count is the size less these.
  @reserved_keys [:root, :max_leaves]

  @opaque t :: :ets.table()

  @doc """
  A table holding the root derived from `seed`, caching at most
  `max_leaves` signed leaves. Owned by the caller.
  """
  @spec new(binary(), pos_integer()) :: t()
  def new(seed, max_leaves \\ @default_max_leaves)
      when is_integer(max_leaves) and max_leaves > 0 do
    table = :ets.new(__MODULE__, [:public, :set, read_concurrency: true])
    :ets.insert(table, {:root, CA.root(seed)})
    :ets.insert(table, {:max_leaves, max_leaves})
    table
  end

  @doc "The root certificate and key."
  @spec root(t()) :: CA.root()
  def root(table) do
    [{:root, pair}] = :ets.lookup(table, :root)
    pair
  end

  @doc "The root certificate as PEM."
  @spec ca_pem(t()) :: String.t()
  def ca_pem(table), do: table |> root() |> elem(0) |> X509.Certificate.to_pem()

  @doc "The root certificate as DER."
  @spec ca_der(t()) :: binary()
  def ca_der(table), do: table |> root() |> elem(0) |> X509.Certificate.to_der()

  @doc """
  The `:ssl` `cert`/`key` options for `host`, signed by the root.

  A cached leaf is returned and its entry marked as used, which is what
  keeps a host in use out of the way of eviction. A miss signs one, and
  the cache is then brought back to its cap.
  """
  @spec for_host(t(), String.t()) :: keyword()
  def for_host(table, host) do
    now = System.system_time(:second)

    case :ets.lookup(table, {:leaf, host}) do
      [{{:leaf, ^host}, opts, signed_at, _used}] when now - signed_at < @refresh_after_seconds ->
        :ets.update_element(table, {:leaf, host}, {4, tick()})
        opts

      _ ->
        opts = CA.leaf(host, root(table))
        :ets.insert(table, {{:leaf, host}, opts, now, tick()})
        evict_over_cap(table)
        opts
    end
  end

  @doc "How many leaves the table is holding."
  @spec cached_leaves(t()) :: non_neg_integer()
  def cached_leaves(table), do: :ets.info(table, :size) - length(@reserved_keys)

  # When an entry was last handed out, as a strictly increasing integer.
  # Monotonic time, not the wall clock: two leaves signed in the same second
  # still have an order, and a clock that steps does not reorder the cache.
  defp tick, do: System.monotonic_time()

  # Back down to the cap, least recently used first. The scan is over the
  # whole table, whose size is the cap, and it runs only where a *new* host
  # has just been signed — beside an ECDSA signature it is not measurable,
  # and the case it has to survive (a distinct name every connection) is
  # exactly the case that was already paying for one.
  defp evict_over_cap(table) do
    over = cached_leaves(table) - max_leaves(table)

    if over > 0 do
      table
      |> :ets.select([{{{:leaf, :"$1"}, :_, :_, :"$2"}, [], [{{:"$2", :"$1"}}]}])
      |> Enum.sort()
      |> Enum.take(over)
      |> Enum.each(fn {_used, host} -> :ets.delete(table, {:leaf, host}) end)
    end

    :ok
  end

  defp max_leaves(table) do
    [{:max_leaves, max}] = :ets.lookup(table, :max_leaves)
    max
  end
end
