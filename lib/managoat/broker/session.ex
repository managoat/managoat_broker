defmodule Managoat.Broker.Session do
  @moduledoc """
  What a proxy token resolves to: the rules the proxy may apply, what to do
  with a host no rule names, when the token stops working, and an opaque
  `meta` the host fills for its own logging.

  A `Managoat.Broker.Store` returns one of these from `lookup/1` with the
  credentials inside `rules` already decrypted. How it is stored, hashed,
  encrypted or swept is the store's business; the proxy looks a token up
  once per CONNECT tunnel and per absolute-form request.

  Set `authorization` to a non-secret, server-controlled reference to opt
  into `c:Managoat.Broker.Store.authorize/2` (or its instance form) before
  each HTTP request. It should pin the session and credential generation;
  it is never populated from a request header. The returned rules apply
  only to that request. The original reference, expiry, policy and metadata
  stay pinned for the connection. `nil` preserves lookup-only behavior.
  Initial rules still govern CONNECT reachability under `:deny`; they can
  contain patterns without credentials. They are never an authorization
  fallback. The reference is not included in request telemetry.

  `meta` travels unchanged into every `[:managoat, :broker, :request]`
  telemetry event for a request served under the session, so a host that
  puts a conversation id and a user id there gets them back on each log
  line without the library knowing what either is.
  """

  alias Managoat.Broker.Rule

  @type policy :: :passthrough | :deny

  @type t :: %__MODULE__{
          rules: [Rule.t()],
          authorization: term() | nil,
          unmatched_host_policy: policy(),
          expires_at: DateTime.t() | nil,
          meta: map()
        }

  defstruct authorization: nil,
            rules: [],
            unmatched_host_policy: :passthrough,
            expires_at: nil,
            meta: %{}

  @doc "True when `expires_at` is set and in the past."
  @spec expired?(t(), DateTime.t()) :: boolean()
  def expired?(%__MODULE__{expires_at: nil}, _now), do: false

  def expired?(%__MODULE__{expires_at: %DateTime{} = at}, now),
    do: DateTime.compare(at, now) == :lt
end
