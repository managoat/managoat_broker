defmodule Managoat.Broker.ProtectedRule do
  @moduledoc """
  Server-controlled policy for one non-exportable bearer per session.

  The host supplies an exact lowercase host, port, paths, public identity
  and its header name, allowed HTTP methods, and an allowlist of ordinary request headers. TRACE
  and CONNECT are never allowed. A path
  ending in `/` permits descendants; other paths match exactly. Paths are
  origin-form and reject escapes, dot segments, repeated slashes, backslashes
  and fragments.

  ## Queries

  `query` says what a request target's query string does on a protected
  route. The default, `:refuse`, denies any target holding a `?` (a bare
  `path?` included) with a `403` and `error: :protected_query`, before the
  credential is resolved: a route is pinned so the bearer goes to one
  operation, and a query the sandbox wrote is a parameter to that operation
  that nobody pinned. `:allow` forwards the query unchanged, never
  templated, and is for a host that has decided its routes take one.

  Set Session.protected to this policy with http_only: true and a non-nil
  authorization reference. No bearer belongs in this struct. The host's
  authorization callback checks the durable session/grant binding and returns
  a ProtectedCredential for each request tagged `protected: true`.

  Ordinary injection rules matching a protected request conflict and fail
  closed; passthrough rules are harmless. Other destinations use ordinary
  rules without access to the protected credential. Requests to the protected
  host must use its pinned HTTPS port and routes. The proxy supplies Host,
  Authorization and the identity header itself. Only allowlisted headers
  and Content-Length survive. Chunked requests/trailers are refused; streamed
  responses are supported. Hosts must verify this contract against their
  clients and must not let tenant configuration construct or widen policies.

  ## The bearer in a response

  The sandbox never holds the bearer, so a response that repeats it (an
  origin echoing the request, a CDN error page, a debug endpoint) would be
  the one way it gets there. Every response to a protected request is
  therefore searched for the bearer it was sent with, and **refused, not
  scrubbed**, if it holds it. There is no option to turn this off.

    * The request goes out with `Accept-Encoding: identity`, whatever the
      client sent and whether or not `allowed_headers` names it. A response
      that carries any other `Content-Encoding` anyway cannot be searched
      and is refused (`error: :protected_response_encoded`).
    * The whole response head is searched before any of it is released.
    * The body is searched as it streams, decoded from chunked framing, and
      is never accumulated. Bytes that could be the start of the bearer are
      held until the next read settles them, so a value split across reads
      or chunks is caught before its first half is forwarded; at most
      `byte_size(bearer) - 1` bytes wait, and ordinarily none do. A chunk
      extension on such a response is refused as malformed.
    * On a match (`error: :credential_reflected`) nothing more is
      forwarded and both connections close. Where the sandbox has not been
      sent any of the response yet it gets a fixed `502` instead. The
      request event carries the session's `meta`, the route and the rule;
      a warning is logged with the same. Neither holds the bearer or the
      bytes that matched.

  What is recognised is the bearer's exact bytes, which any longer string
  holding it (`Bearer <value>`) contains, and its JSON spelling with `/`
  written `\\/`. What is **not**: base64, hex, percent-encoding or any other
  transformation; a truncated or partial copy; a body compressed without
  saying so; a response on any other request or connection; and any secret
  other than this bearer.
  """
  alias Managoat.Broker.{
    HTTP,
    HTTPOnly,
    Injector,
    ProtectedCredential,
    ReflectionGuard,
    Rule,
    Session
  }

  @enforce_keys [:host, :port, :paths, :methods, :identity, :identity_header, :allowed_headers]
  defstruct [
    :name,
    :host,
    :port,
    :paths,
    :methods,
    :identity,
    :identity_header,
    :allowed_headers,
    query: :refuse
  ]

  @type t :: %__MODULE__{
          name: binary() | nil,
          host: binary(),
          port: :inet.port_number(),
          paths: [binary()],
          methods: [binary()],
          identity: binary(),
          identity_header: binary(),
          allowed_headers: [binary()],
          query: :refuse | :allow
        }
  @reserved ~w(authorization host connection proxy-authorization proxy-connection upgrade content-length transfer-encoding trailer te cookie set-cookie forwarded x-forwarded-host x-forwarded-proto x-original-url x-rewrite-url)
  @header ~r/\A[!#$%&'*+.^_`|~0-9a-z-]+\z/
  @bearer ~r/\A[A-Za-z0-9._~+\/-]+=*\z/

  @doc "Validate a persisted session policy without resolving any credentials."
  def valid_session?(%Session{protected: nil}), do: true

  def valid_session?(%Session{
        protected: %__MODULE__{} = policy,
        http_only: true,
        authorization: ref
      })
      when not is_nil(ref) do
    HTTP.valid_host?(policy.host) and not String.contains?(policy.host, "*") and
      policy.host == String.downcase(policy.host) and
      is_integer(policy.port) and policy.port in 1..65_535 and
      is_list(policy.paths) and policy.paths != [] and Enum.all?(policy.paths, &safe_path?/1) and
      is_list(policy.methods) and policy.methods != [] and
      Enum.all?(policy.methods, &(&1 in ~w(GET POST PUT PATCH DELETE HEAD OPTIONS))) and
      safe_identity?(policy.identity) and allowed_header?(policy.identity_header) and
      is_list(policy.allowed_headers) and Enum.all?(policy.allowed_headers, &allowed_header?/1) and
      (is_nil(policy.name) or is_binary(policy.name)) and
      query(policy) in [:refuse, :allow]
  rescue
    _ -> false
  end

  def valid_session?(_session), do: false

  @doc false
  def destination?(%Session{protected: %__MODULE__{host: pinned, port: port}}, host, port),
    do: String.downcase(host) == pinned

  def destination?(_session, _host, _port), do: false

  @doc false
  def select(%Session{protected: nil}, _request), do: :ordinary

  def select(%Session{protected: policy}, request) do
    if String.downcase(request.host) == policy.host do
      cond do
        not (request.scheme == :https and request.port == policy.port and
               request.method in policy.methods and allowed_target?(policy, request.target)) ->
          {:error, :protected_destination}

        query(policy) != :allow and String.contains?(request.target, "?") ->
          {:error, :protected_query}

        true ->
          {:ok, policy}
      end
    else
      :ordinary
    end
  end

  @doc false
  def prepare(policy, session, request, headers) do
    cond do
      Enum.any?(session.rules, &conflicting?(&1, request)) ->
        {:error, :protected_conflict}

      HTTP.header(headers, "transfer-encoding") != nil ->
        {:error, :unsafe_request}

      true ->
        allowed = ["content-length" | policy.allowed_headers]
        kept = Enum.filter(headers, fn {key, _} -> String.downcase(key) in allowed end)
        # These are never delegated to tenant headers, even if mistakenly
        # named in the ordinary allowlist.
        # Nor is the response's coding: a compressed body cannot be searched
        # for the bearer, so the proxy asks for none on the client's behalf.
        kept =
          Enum.reject(kept, fn {key, _} ->
            String.downcase(key) in [policy.identity_header, "accept-encoding"]
          end)

        {:ok, [{"host", authority(policy)}, {"accept-encoding", "identity"} | kept]}
    end
  end

  @doc false
  def inject(policy, %ProtectedCredential{bearer: bearer, identity: identity}, headers, target) do
    if identity == policy.identity and is_binary(bearer) and Regex.match?(@bearer, bearer) do
      outgoing = [
        {"authorization", "Bearer " <> bearer},
        {policy.identity_header, identity} | headers
      ]

      with :ok <- HTTPOnly.check_request(true, "POST", outgoing) do
        {:ok, outgoing, target, policy}
      end
    else
      {:error, :authorization_unavailable}
    end
  end

  @doc false
  # What the response to this request is searched for: nothing, unless the
  # rule that applied was a protected one, and then the bearer `inject/4`
  # just wrote. Read back off the outgoing head so that the value searched
  # for is the value sent.
  def response_secrets(%__MODULE__{}, headers) do
    "Bearer " <> bearer = HTTP.header(headers, "authorization")
    ReflectionGuard.needles(bearer)
  end

  def response_secrets(_rule, _headers), do: nil

  # A policy persisted by a release that had no `query` key has none, and
  # reads as the default rather than as an invalid session.
  defp query(policy), do: Map.get(policy, :query, :refuse)

  defp conflicting?(%Rule{scheme: :passthrough}, _request), do: false

  defp conflicting?(%Rule{} = rule, request),
    do: Injector.matches?(rule.pattern, request.host, request.port, request.target)

  defp allowed_target?(policy, target) do
    path = target |> String.split("?", parts: 2) |> hd()

    safe_path?(path) and
      Enum.any?(policy.paths, fn allowed ->
        if String.ends_with?(allowed, "/"),
          do: String.starts_with?(path, allowed),
          else: path == allowed
      end)
  end

  defp safe_path?("/" <> _ = path) do
    not Regex.match?(~r/[\x00-\x20\x7F%\\?#]/, path) and
      not String.contains?(path, "//") and
      not Enum.any?(String.split(path, "/"), &(&1 in [".", ".."]))
  end

  defp safe_path?(_path), do: false
  defp safe_identity?(value), do: is_binary(value) and Regex.match?(~r/\A[!-~]+\z/, value)

  defp allowed_header?(name),
    do: is_binary(name) and Regex.match?(@header, name) and name not in @reserved

  defp authority(%{host: host, port: port}) do
    host = if String.contains?(host, ":"), do: "[#{host}]", else: host
    if port == 443, do: host, else: "#{host}:#{port}"
  end
end
