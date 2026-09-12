defmodule Managoat.Broker.Store do
  @moduledoc """
  Session lookup and optional per-request authorization from the host.

  A sandbox dials the proxy with `Proxy-Authorization: Basic
  base64(token:label)`. The proxy hands the raw `token` to the store and
  serves the connection under the `Managoat.Broker.Session` it gets back,
  or refuses it with 407. Everything else about sessions (creating one,
  hashing the token before storing it, encrypting the rules, releasing a
  conversation's sessions, sweeping expired rows) is the host's business:
  it touches the host's tables and its key hierarchy, and the proxy never
  needs any of it.

  The `label` half of the credential is not passed on. It exists because
  some clients (git) refuse a proxy URL with a user and no password; with a
  random per-session token the token alone is the binding.

  ## Configuring the store

  The listener's `store:` option is either a module implementing this
  behaviour, called as `module.lookup(token)`, or a `{module, instance}`
  pair, called as `module.lookup(instance, token)` for a store that has
  several instances (the in-memory store in a test, one per listener).

  `Managoat.Broker.Store.Memory` is the reference store: an in-memory map,
  for tests and for a consumer without a database.
  """

  alias Managoat.Broker.{Rule, Session}

  @doc "The session for a raw token, or `:error` for a token the store does not know."
  @callback lookup(token :: binary()) :: {:ok, Session.t()} | :error

  @doc "The same, for a store with several instances (see the moduledoc)."
  @callback lookup(instance :: term(), token :: binary()) :: {:ok, Session.t()} | :error

  @typedoc "Actual proxy destination and original request line, before rule processing."
  @type request :: %{
          scheme: :http | :https,
          host: binary(),
          port: :inet.port_number(),
          method: binary(),
          target: binary()
        }

  @typedoc "Fresh rules for this request, or a bounded refusal reason."
  @type authorization_result :: {:ok, [Rule.t()]} | {:error, :denied | :unavailable}

  @doc """
  Admit one HTTP request for the session's server-controlled authorization
  reference and resolve its current rules. Called only when the session's
  `authorization` is non-nil, including on every request within CONNECT.

  The host must check durable authority for the pinned reference, serialize
  that check with revocation, and return credentials from the same read.
  Return `{:error, :denied}` for revoked/missing authority and
  `{:error, :unavailable}` when it cannot be checked. Never return a cached
  success on store failure. Bound database and provider waits in the host;
  the callback runs synchronously in the connection handler. Release all
  locks before returning: a request admitted before revocation may finish,
  and the proxy holds no authorization work through its response stream.

  The request contains the actual proxy destination (not its Host header)
  and the original target (which may contain a query). Do not log it as a
  whole. This callback is an HTTP admission primitive, not a protected
  credential compiler or authorization of traffic after a protocol upgrade.
  Hosts requiring that boundary must also set `Session.http_only: true`
  and use protected rule processing. Protected credential compilation and
  draining legacy connections are not implemented here yet.
  """
  @callback authorize(authorization :: term(), request()) :: authorization_result()

  @doc "The same, for a store with several instances."
  @callback authorize(instance :: term(), authorization :: term(), request()) ::
              authorization_result()

  @optional_callbacks lookup: 1, lookup: 2, authorize: 2, authorize: 3

  @typedoc "What the listener's `store:` option accepts."
  @type ref :: module() | {module(), term()}

  @doc false
  @spec lookup(ref(), binary()) :: {:ok, Session.t()} | :error
  def lookup(module, token) when is_atom(module), do: module.lookup(token)
  def lookup({module, instance}, token) when is_atom(module), do: module.lookup(instance, token)

  @doc false
  @spec authorize(ref(), Session.t(), request()) ::
          {:ok, Session.t()} | {:error, :authorization_denied | :authorization_unavailable}
  def authorize(_store, %Session{authorization: nil} = session, _request), do: {:ok, session}

  def authorize(store, %Session{} = session, request) do
    if Session.expired?(session, DateTime.utc_now()) do
      {:error, :authorization_denied}
    else
      store
      |> call_authorize(session.authorization, request)
      |> authorized_session(session)
    end
  rescue
    _ -> {:error, :authorization_unavailable}
  catch
    _, _ -> {:error, :authorization_unavailable}
  end

  # A missing optional callback raises UndefinedFunctionError and is caught
  # above. Its absence can never fall back to the session's cached rules.
  defp call_authorize(module, authorization, request) when is_atom(module),
    do: module.authorize(authorization, request)

  defp call_authorize({module, instance}, authorization, request),
    do: module.authorize(instance, authorization, request)

  defp authorized_session({:ok, rules}, session) when is_list(rules) do
    if Enum.all?(rules, &is_struct(&1, Rule)),
      do: {:ok, %{session | rules: rules}},
      else: {:error, :authorization_unavailable}
  end

  defp authorized_session({:error, :denied}, _session), do: {:error, :authorization_denied}
  defp authorized_session(_result, _session), do: {:error, :authorization_unavailable}
end
