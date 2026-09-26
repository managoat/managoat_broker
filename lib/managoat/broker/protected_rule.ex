defmodule Managoat.Broker.ProtectedRule do
  @moduledoc """
  Server-controlled policy for one non-exportable bearer per session.

  The host supplies an exact lowercase host, port, paths, public identity
  and its header name, allowed HTTP methods (or, in place of paths and
  methods, per-route `routes`; see "Routes"), and an allowlist of ordinary
  request headers. TRACE
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

  `{:only, names}` is the narrow middle, and is available only on a route in
  `routes` (below). A query is admitted when every parameter's name is one of
  `names`, and is then forwarded byte for byte. Anything else is
  `:protected_query`. Names are compared as the raw bytes on the wire, so no
  spelling of a name can mean one thing here and another to the origin:

    * the query is `name=value` pairs joined by `&`, each with a `=`; an
      empty query (`path?`), an empty pair (`a=1&&b=2`, a trailing `&`) or a
      pair without `=` is malformed and refused;
    * a name must equal a pinned name exactly, case included; a name holding
      `%`, `+` or anything else outside the pinned characters cannot;
    * each pinned name may appear at most once, because origins disagree
      about which of two copies wins;
    * a value is unreserved characters, `%XX` escapes and
      `+ , : @ ! $ ' ( ) * /`; `;` (a separator to some servers), `=`, `?`,
      `#` and a malformed escape are refused, as is a value that decodes to
      a control character.

  Why a pinned name set is acceptable where a free query was not: what a
  free query admits is an operation nobody chose, since every parameter the
  origin understands becomes reachable under the bearer. A pinned name set
  puts the choice of parameters back with the host, and leaves the sandbox
  only their values, which is what it already controls on the same route in
  the body. The values are still the sandbox's: the host should pin only
  parameters whose every value is harmless on that route. The bearer is never
  put into a query by the broker, and the response is searched for it
  whatever the query was (below).

  ## Routes

  `paths`, `methods` and `query` apply jointly: every method and the query
  policy hold on every path. A host that needs a narrower policy on one path
  than on another sets `routes` instead, a list of maps:

      routes: [
        %{path: "/backend-api/codex/responses", methods: ["POST"], query: :refuse},
        %{path: "/backend-api/codex/models", methods: ["GET"],
          query: {:only, ["client_version"]}}
      ]

  A request is admitted when one route matches its path (with the same
  exact/subtree rule as `paths`), its method, and its query. A request that
  matches no route's path and method is `:protected_destination`; one that
  does, but whose query none of those routes admits, is `:protected_query`.
  Overlapping routes are a union. `query` is optional in a route and
  defaults to `:refuse`; a route with any other key is invalid.

  `routes` replaces the joint fields rather than adding to them. A policy
  that sets `routes` must leave `paths` and `methods` `nil` (or `[]`) and
  `query` at its default, so that a policy written half one way and half
  the other is refused by `valid_session?/1` rather than read as whichever
  half wins. A policy with no `routes` (including one persisted before the
  key existed) behaves exactly as before.

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

  @enforce_keys [:host, :port, :identity, :identity_header, :allowed_headers]
  defstruct [
    :name,
    :host,
    :port,
    :paths,
    :methods,
    :identity,
    :identity_header,
    :allowed_headers,
    query: :refuse,
    routes: nil
  ]

  @typedoc "What a query string may do on a route. `{:only, _}` is for `routes` only."
  @type query_policy :: :refuse | :allow | {:only, [binary(), ...]}

  @typedoc "One protected route: a path, its methods, and its query policy."
  @type route :: %{
          required(:path) => binary(),
          required(:methods) => [binary(), ...],
          optional(:query) => query_policy()
        }

  @type t :: %__MODULE__{
          name: binary() | nil,
          host: binary(),
          port: :inet.port_number(),
          paths: [binary()] | nil,
          methods: [binary()] | nil,
          identity: binary(),
          identity_header: binary(),
          allowed_headers: [binary()],
          query: :refuse | :allow,
          routes: [route(), ...] | nil
        }
  @reserved ~w(authorization host connection proxy-authorization proxy-connection upgrade content-length transfer-encoding trailer te cookie set-cookie forwarded x-forwarded-host x-forwarded-proto x-original-url x-rewrite-url)
  @header ~r/\A[!#$%&'*+.^_`|~0-9a-z-]+\z/
  @bearer ~r/\A[A-Za-z0-9._~+\/-]+=*\z/
  @methods ~w(GET POST PUT PATCH DELETE HEAD OPTIONS)
  @param_name ~r/\A[A-Za-z0-9._~-]+\z/
  @param_value ~r/\A(?:[A-Za-z0-9._~+,:@!$'()*\/-]|%[0-9A-Fa-f]{2})*\z/

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
      valid_routes?(policy) and
      safe_identity?(policy.identity) and allowed_header?(policy.identity_header) and
      is_list(policy.allowed_headers) and Enum.all?(policy.allowed_headers, &allowed_header?/1) and
      (is_nil(policy.name) or is_binary(policy.name))
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
      matching =
        if request.scheme == :https and request.port == policy.port,
          do: matching_routes(policy, request.method, request.target),
          else: []

      cond do
        matching == [] -> {:error, :protected_destination}
        Enum.any?(matching, &query_allowed?(&1.query, request.target)) -> {:ok, policy}
        true -> {:error, :protected_query}
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
  # reads as the default rather than as an invalid session. Likewise one
  # persisted before `routes` existed has no `routes` key, and reads as a
  # policy without routes.
  defp query(policy), do: Map.get(policy, :query, :refuse)
  defp explicit_routes(policy), do: Map.get(policy, :routes)

  # Every policy as a list of routes. Without `routes`, the joint fields are
  # one route per path, each carrying all the methods and the one query
  # policy, which is exactly what they meant before routes existed.
  defp routes(policy) do
    case explicit_routes(policy) do
      nil ->
        for path <- policy.paths, do: %{path: path, methods: policy.methods, query: query(policy)}

      routes ->
        Enum.map(
          routes,
          &%{path: &1.path, methods: &1.methods, query: Map.get(&1, :query, :refuse)}
        )
    end
  end

  defp valid_routes?(policy) do
    case explicit_routes(policy) do
      nil ->
        valid_paths?(policy.paths) and valid_methods?(policy.methods) and
          query(policy) in [:refuse, :allow]

      routes ->
        # `routes` replaces the joint fields. One set alongside the other is
        # a policy written two ways, and nobody can say which was meant.
        is_list(routes) and routes != [] and Enum.all?(routes, &valid_route?/1) and
          Map.get(policy, :paths) in [nil, []] and Map.get(policy, :methods) in [nil, []] and
          query(policy) == :refuse
    end
  end

  defp valid_route?(%{path: path, methods: methods} = route) when not is_struct(route) do
    Enum.all?(Map.keys(route), &(&1 in [:path, :methods, :query])) and safe_path?(path) and
      valid_methods?(methods) and valid_query_policy?(Map.get(route, :query, :refuse))
  end

  defp valid_route?(_route), do: false

  defp valid_paths?(paths),
    do: is_list(paths) and paths != [] and Enum.all?(paths, &safe_path?/1)

  defp valid_methods?(methods),
    do: is_list(methods) and methods != [] and Enum.all?(methods, &(&1 in @methods))

  defp valid_query_policy?(policy) when policy in [:refuse, :allow], do: true

  defp valid_query_policy?({:only, names}) when is_list(names) and names != [] do
    Enum.all?(names, &(is_binary(&1) and Regex.match?(@param_name, &1))) and
      Enum.uniq(names) == names
  end

  defp valid_query_policy?(_policy), do: false

  defp matching_routes(policy, method, target) do
    path = target |> String.split("?", parts: 2) |> hd()

    if safe_path?(path) do
      Enum.filter(routes(policy), &(method in &1.methods and path_allowed?(&1.path, path)))
    else
      []
    end
  end

  defp path_allowed?(allowed, path) do
    if String.ends_with?(allowed, "/"),
      do: String.starts_with?(path, allowed),
      else: path == allowed
  end

  defp query_allowed?(:allow, _target), do: true

  defp query_allowed?(policy, target) do
    case String.split(target, "?", parts: 2) do
      [_path] -> true
      [_path, query] -> policy != :refuse and pinned_query?(policy, query)
    end
  end

  # `{:only, names}`: the raw query, pair by pair, before anything decodes
  # it. See "Queries" in the moduledoc for each refusal.
  defp pinned_query?({:only, names}, query) do
    pairs = String.split(query, "&")

    Enum.all?(pairs, fn pair ->
      case String.split(pair, "=", parts: 2) do
        [name, value] -> name in names and pinned_value?(value)
        [_bare] -> false
      end
    end) and length(Enum.uniq_by(pairs, &hd(String.split(&1, "=", parts: 2)))) == length(pairs)
  end

  defp pinned_value?(value) do
    Regex.match?(@param_value, value) and
      not Regex.match?(~r/[\x00-\x1F\x7F]/, URI.decode_www_form(value))
  end

  defp conflicting?(%Rule{scheme: :passthrough}, _request), do: false

  defp conflicting?(%Rule{} = rule, request),
    do: Injector.matches?(rule.pattern, request.host, request.port, request.target)

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
