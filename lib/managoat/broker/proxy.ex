defmodule Managoat.Broker.Proxy do
  @moduledoc """
  The egress proxy a brokered sandbox dials: one client connection.

  The listener (`Managoat.Broker`) is plaintext HTTP; TLS toward the
  sandbox, if any, is the ingress's job. It speaks the two things a forward
  proxy speaks: `CONNECT host:443` for HTTPS, and absolute-form requests
  (`GET http://host/path`) for plain HTTP. The client authenticates with
  the session token in its proxy URL, which arrives as
  `Proxy-Authorization: Basic base64(token:label)`; the token is looked up
  in the `Managoat.Broker.Store` once per connection.

  On `CONNECT` the proxy opens the upstream TLS connection first (a host it
  cannot reach is a `502` before the tunnel exists), answers `200`, then
  completes a TLS handshake with the *sandbox* using a leaf for that host
  signed by the listener's `Managoat.Broker.CA`, which the sandbox trusts
  because the host installed the root. Inside the tunnel it reads each
  request head, lets `Managoat.Broker.Injector` rewrite the headers, and
  forwards the head and body to the origin. Bytes coming back are relayed
  untouched and unparsed, so a streaming model reply streams.

  Every request the proxy decides about emits `[:managoat, :broker,
  :request]` with `%{count: 1}` and the metadata `method`, `host`, `path`,
  `outcome` (`:injected`, `:passthrough` or `:denied`), `rule` (the matched
  rule's name or nil) and `meta` (the session's, unchanged). Never a header,
  never a body, and `path` is the URL path only — never a query string or a
  fragment, on either request path, because a query can carry a credential
  the proxy never saw. The origin still receives the target unchanged. The
  host attaches a handler and writes its log line.

  Beside it, every connection the proxy decides about emits `[:managoat,
  :broker, :connect]` with `%{count: 1}` and the metadata `host`, `port`,
  `outcome` (`:ok`, `:upstream_failed`, `:denied` or `:unauthenticated`)
  and `meta`. That event is emitted on every path, the ones that never
  reach an origin included, so "how much of this broker's egress is
  failing" is a ratio over it rather than a count with no denominator. On
  `:unauthenticated` there is no session and no destination yet, so `host`
  and `port` are nil and `meta` is empty.

  This module is a `ThousandIsland.Handler`; ThousandIsland calls its
  `child_spec/1` for every accepted connection, which is why the listener's
  own child spec lives on `Managoat.Broker` and not here.
  """

  use ThousandIsland.Handler

  require Logger

  alias Managoat.Broker.{Certs, HTTP, Injector, Session, Store}
  alias ThousandIsland.Socket

  @head_timeout 30_000
  @idle_timeout 300_000
  @connect_timeout 10_000

  # How many times one connection may be answered with a `407` before the
  # proxy stops reading from it. Two is enough for the negotiation this
  # exists for (bare request, then the credentialed retry); the third is
  # slack for a client that re-negotiates once.
  @auth_attempts 3

  # ---------------------------------------------------------------------------
  # One client connection

  @impl ThousandIsland.Handler
  def handle_connection(socket, opts) do
    state = %{
      store: Keyword.fetch!(opts, :store),
      certs: Keyword.fetch!(opts, :certs),
      allow_private_upstreams: Keyword.get(opts, :allow_private_upstreams, false),
      upstream_ssl_options: Keyword.get(opts, :upstream_ssl_options, [])
    }

    serve_client(socket, "", state, @auth_attempts)
  end

  # One request head off this connection, and what the proxy does about it.
  # Recurses only on `{:retry, _}`, which is a client coming back with a
  # credential after a `407`; every other outcome ends the connection.
  defp serve_client(socket, buffer, state, attempts) do
    with {:ok, head, rest} <- read_head(socket, buffer, @head_timeout),
         {:ok, session} <- authenticate(socket, head, rest, attempts, state),
         {:ok, {host, port}, target} <- destination(socket, head) do
      case head.method do
        "CONNECT" ->
          if reachable?(session, host, port) do
            tunnel(socket, host, port, session, state)
          else
            log_request(session, head, host, {:error, :denied})
            connect_event(session, host, port, :denied)
            reply(socket, 403, "Forbidden")
            {:close, state}
          end

        _ ->
          forward_plain(socket, head, rest, host, port, target, session, state)
      end
    else
      {:retry, rest} -> serve_client(socket, rest, state, attempts - 1)
      {:error, _} -> {:close, state}
    end
  end

  # Under `deny`, a host no rule could match is refused at CONNECT, before
  # a tunnel exists; paths are only known per request, so a host that
  # matches some rule still gets its per-request check inside the tunnel.
  defp reachable?(%Session{unmatched_host_policy: :deny, rules: rules}, host, port) do
    Enum.any?(rules, &Injector.host_matches?(&1.pattern, host, port))
  end

  defp reachable?(_session, _host, _port), do: true

  defp read_head(socket, buffer, timeout) do
    case HTTP.parse_request(buffer) do
      {:ok, head, rest} ->
        {:ok, head, rest}

      {:error, reason} ->
        reply(socket, 400, "Bad Request")
        {:error, reason}

      {:more, _} ->
        case Socket.recv(socket, 0, timeout) do
          {:ok, data} -> read_head(socket, buffer <> data, timeout)
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp authenticate(socket, head, rest, attempts, state) do
    with {:ok, token} <- proxy_token(head.headers),
         {:ok, %Session{} = session} <- lookup(state.store, token),
         false <- Session.expired?(session, DateTime.utc_now()) do
      {:ok, session}
    else
      reason ->
        log_refusal(refusal(reason))
        connect_event(nil, nil, nil, :unauthenticated)
        challenge(socket, head, rest, attempts)
    end
  end

  # A request with no `Proxy-Authorization` is the first half of a
  # negotiation, not an incident: it is what a client that asks the proxy
  # which scheme to use sends, and it is what a credential-less liveness
  # probe sends every thirty seconds. A token that is wrong or expired is
  # the other thing entirely, and stays at `:info` where it can be seen.
  defp log_refusal(:no_credentials),
    do: Logger.debug("broker: no credentials, challenging")

  defp log_refusal(reason),
    do: Logger.info("broker: refused connection: #{inspect(reason)}")

  # The `407` itself. RFC 9110 makes the challenge an invitation to retry,
  # so the connection stays open for that retry: a client on
  # `http.proxyAuthMethod=anyauth` — git's default — sent its first request
  # bare *in order to* learn the scheme, and retries on the same socket. A
  # proxy that closes here turns the challenge into a dead end, and inside a
  # sandbox that presents as "the network is broken".
  #
  # Held open only when the bytes after the head are the next request: a
  # request carrying a body would leave that body in the stream with nothing
  # to consume it, and reading a body the proxy is refusing to forward is
  # work an unauthenticated client should not be able to ask for. `CONNECT`,
  # the case this exists for, never has one. `@auth_attempts` bounds the
  # rest, so a client that never authenticates cannot hold the socket past
  # a few head timeouts.
  defp challenge(socket, head, rest, attempts) do
    hold? = attempts > 1 and HTTP.body_framing(head) == :none

    keep_alive = if hold?, do: [{"proxy-connection", "Keep-Alive"}], else: []

    reply(
      socket,
      407,
      "Proxy Authentication Required",
      [{"proxy-authenticate", ~s(Basic realm="managoat-broker")}] ++ keep_alive
    )

    if hold?, do: {:retry, rest}, else: {:error, :unauthenticated}
  end

  defp refusal({:error, reason}), do: reason
  defp refusal(:error), do: :unknown_token
  defp refusal(true), do: :expired

  defp lookup(store, token) do
    case Store.lookup(store, token) do
      {:ok, %Session{}} = ok -> ok
      _ -> :error
    end
  end

  defp proxy_token(headers) do
    with "Basic " <> encoded <- HTTP.header(headers, "proxy-authorization") || "",
         {:ok, pair} <- Base.decode64(String.trim(encoded)),
         [token, _label] <- String.split(pair, ":", parts: 2) do
      {:ok, token}
    else
      _ -> {:error, :no_credentials}
    end
  end

  defp destination(socket, head) do
    case HTTP.destination(head) do
      {:ok, _, _} = ok ->
        ok

      {:error, :bad_target} ->
        reply(socket, 400, "Bad Request")
        {:error, :bad_target}
    end
  end

  # ---------------------------------------------------------------------------
  # CONNECT: a TLS tunnel the proxy terminates on both ends

  defp tunnel(socket, host, port, session, state) do
    with {:ok, address} <- resolve(socket, host, port, state),
         {:ok, upstream} <- connect_tls(socket, address, host, port, state) do
      Socket.send(socket, "HTTP/1.1 200 Connection established\r\n\r\n")
      connect_event(session, host, port, :ok)

      # The handshake runs on the raw socket: the handler is synchronous
      # from here to the end of the tunnel, so the transport switch stays
      # ours. (`Socket.upgrade` does not compose with a synchronous handler.)
      # Closing the TLS socket closes the TCP one under it, and the
      # handler's own close afterwards is a no-op on a closed port.
      case :ssl.handshake(socket.socket, client_ssl_options(state.certs, host), @head_timeout) do
        {:ok, client} ->
          relay = spawn_link(fn -> pump(upstream, client) end)
          result = serve(client, upstream, host, port, session, "")
          :ssl.close(upstream)
          Process.exit(relay, :kill)
          :ssl.close(client)
          {result, state}

        {:error, reason} ->
          Logger.info("broker: sandbox TLS handshake for #{host} failed: #{inspect(reason)}")
          :ssl.close(upstream)
          {:close, state}
      end
    else
      {:error, :private_upstream} ->
        connect_event(session, host, port, :denied)
        {:close, state}

      {:error, _} ->
        connect_event(session, host, port, :upstream_failed)
        {:close, state}
    end
  end

  # The origin's address, vetted. A sandbox may name any host, and the proxy
  # sits on the operator's network, so a name that resolves into a private,
  # loopback or link-local range is refused before any connection exists:
  # otherwise the broker is a door from a third-party sandbox into the
  # operator's network. The connection is then made to the vetted address,
  # not the name, so a rebinding DNS answer between check and dial changes
  # nothing. Off only for a test rig (`allow_private_upstreams: true`),
  # whose origins are on localhost.
  defp resolve(socket, host, port, state) do
    case :inet.getaddrs(String.to_charlist(host), :inet) do
      {:ok, [address | _]} ->
        if private?(address) and not state.allow_private_upstreams do
          Logger.info("broker: refused #{host}:#{port}: resolves to #{:inet.ntoa(address)}")
          reply(socket, 403, "Forbidden")
          {:error, :private_upstream}
        else
          {:ok, address}
        end

      {:error, reason} ->
        Logger.info("broker: upstream #{host}:#{port} did not resolve: #{inspect(reason)}")
        reply(socket, 502, "Bad Gateway")
        {:error, reason}
    end
  end

  @doc """
  Is this an address the proxy must not dial on a sandbox's behalf? RFC
  1918, loopback, link-local (including the cloud metadata address), CGNAT,
  and the unspecified address.
  """
  @spec private?(:inet.ip4_address()) :: boolean()
  def private?({10, _, _, _}), do: true
  def private?({127, _, _, _}), do: true
  def private?({169, 254, _, _}), do: true
  def private?({172, b, _, _}) when b in 16..31, do: true
  def private?({192, 168, _, _}), do: true
  def private?({100, b, _, _}) when b in 64..127, do: true
  def private?({0, _, _, _}), do: true
  def private?(_), do: false

  defp connect_tls(socket, address, host, port, state) do
    case :ssl.connect(address, port, upstream_ssl_options(host, state), @connect_timeout) do
      {:ok, _} = ok ->
        ok

      {:error, reason} ->
        Logger.info("broker: upstream #{host}:#{port} unreachable: #{inspect(reason)}")
        reply(socket, 502, "Bad Gateway")
        {:error, reason}
    end
  end

  # Upstream → sandbox, byte for byte. When the origin closes, the sandbox's
  # side is closed too, which ends `serve/6`.
  defp pump(upstream, client) do
    case :ssl.recv(upstream, 0) do
      {:ok, data} ->
        case :ssl.send(client, data) do
          :ok -> pump(upstream, client)
          {:error, _} -> :ok
        end

      {:error, _} ->
        :ssl.close(client)
        :ok
    end
  end

  # Sandbox → upstream, one request at a time: head rewritten, body copied.
  defp serve(client, upstream, host, port, session, buffer) do
    case HTTP.parse_request(buffer) do
      {:ok, head, rest} ->
        case Injector.inject(head.headers, host, port, head.target, session) do
          {:ok, headers, target, rule} ->
            # `head` is the target the client sent; `target` is the one to
            # forward. Telemetry is derived from the former, so a
            # substituted credential is never what gets logged.
            log_request(session, head, host, {:ok, rule})
            request = HTTP.encode_request(%{head | headers: headers}, target)

            with :ok <- :ssl.send(upstream, request),
                 {:ok, rest} <- copy_body(client, upstream, HTTP.body_framing(head), rest) do
              if upgrade?(head),
                do: pipe(client, upstream, rest),
                else: serve(client, upstream, host, port, session, rest)
            else
              {:error, _} -> :close
            end

          {:error, reason} ->
            log_refused_request(session, head, host, reason)
            reply(client, 403, "Forbidden", [{"connection", "close"}])
            :close
        end

      {:more, _} ->
        case :ssl.recv(client, 0, @idle_timeout) do
          {:ok, data} -> serve(client, upstream, host, port, session, buffer <> data)
          {:error, _} -> :close
        end

      {:error, _} ->
        reply(client, 400, "Bad Request", [{"connection", "close"}])
        :close
    end
  end

  defp copy_body(client, upstream, framing, buffer) do
    case HTTP.take_body(framing, buffer) do
      {:done, bytes, rest} ->
        send_upstream(upstream, bytes)
        {:ok, rest}

      {:partial, bytes, framing} ->
        send_upstream(upstream, bytes)

        case :ssl.recv(client, 0, @idle_timeout) do
          {:ok, data} -> copy_body(client, upstream, framing, data)
          {:error, reason} -> {:error, reason}
        end
    end
  end

  # A request that upgrades the connection (WebSocket) is the last HTTP on
  # it: what follows is frames, so the client side becomes a byte pipe like
  # the upstream side already is. The upgrade request itself was injected
  # like any other; frames are never rewritten.
  defp upgrade?(%{headers: headers}) do
    case HTTP.header(headers, "upgrade") do
      nil -> false
      _ -> true
    end
  end

  defp pipe(client, upstream, buffered) do
    with :ok <- send_upstream(upstream, buffered),
         {:ok, data} <- :ssl.recv(client, 0, @idle_timeout) do
      pipe(client, upstream, data)
    else
      _ -> :close
    end
  end

  defp send_upstream(_upstream, ""), do: :ok
  defp send_upstream(upstream, bytes), do: :ssl.send(upstream, bytes)

  # ---------------------------------------------------------------------------
  # Absolute-form: one plain-HTTP request, its response, then close

  defp forward_plain(socket, head, rest, host, port, target, session, state) do
    with {:ok, headers, target, rule} <-
           inject_or_deny(socket, head, host, port, target, session),
         {:ok, address} <- resolve(socket, host, port, state),
         {:ok, upstream} <- connect_plain(socket, address, host, port) do
      log_request(session, head, host, {:ok, rule})
      connect_event(session, host, port, :ok)

      headers = [
        {"connection", "close"}
        | Enum.reject(headers, &(String.downcase(elem(&1, 0)) == "connection"))
      ]

      :ok = :gen_tcp.send(upstream, HTTP.encode_request(%{head | headers: headers}, target))

      case copy_body_plain(socket, upstream, HTTP.body_framing(head), rest) do
        :ok -> pump_plain(upstream, socket)
        {:error, _} -> :ok
      end

      :gen_tcp.close(upstream)
      {:close, state}
    else
      {:error, reason} when reason in [:denied, :private_upstream] ->
        connect_event(session, host, port, :denied)
        {:close, state}

      {:error, _} ->
        connect_event(session, host, port, :upstream_failed)
        {:close, state}
    end
  end

  defp inject_or_deny(socket, head, host, port, target, session) do
    case Injector.inject(head.headers, host, port, target, session) do
      {:ok, _, _, _} = ok ->
        ok

      {:error, reason} ->
        log_refused_request(session, head, host, reason)
        reply(socket, 403, "Forbidden")
        {:error, :denied}
    end
  end

  defp connect_plain(socket, address, host, port) do
    case :gen_tcp.connect(address, port, [:binary, active: false], @connect_timeout) do
      {:ok, _} = ok ->
        ok

      {:error, reason} ->
        Logger.info("broker: upstream #{host}:#{port} unreachable: #{inspect(reason)}")
        reply(socket, 502, "Bad Gateway")
        {:error, reason}
    end
  end

  defp copy_body_plain(client, upstream, framing, buffer) do
    case HTTP.take_body(framing, buffer) do
      {:done, bytes, _rest} ->
        if bytes != "", do: :gen_tcp.send(upstream, bytes)
        :ok

      {:partial, bytes, framing} ->
        if bytes != "", do: :gen_tcp.send(upstream, bytes)

        case Socket.recv(client, 0, @idle_timeout) do
          {:ok, data} -> copy_body_plain(client, upstream, framing, data)
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp pump_plain(upstream, client) do
    case :gen_tcp.recv(upstream, 0, @idle_timeout) do
      {:ok, data} ->
        case Socket.send(client, data) do
          :ok -> pump_plain(upstream, client)
          {:error, _} -> :ok
        end

      {:error, _} ->
        :ok
    end
  end

  # ---------------------------------------------------------------------------

  # A pure keyword list, so `Keyword.merge` with the host's options works.
  defp upstream_ssl_options(host, state) do
    [
      mode: :binary,
      active: false,
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      server_name_indication: String.to_charlist(host),
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)],
      alpn_advertised_protocols: ["http/1.1"],
      depth: 5
    ]
    |> Keyword.merge(state.upstream_ssl_options)
  end

  defp client_ssl_options(certs, host) do
    Certs.for_host(certs, host) ++
      [
        alpn_preferred_protocols: ["http/1.1"],
        reuse_sessions: false,
        handshake_timeout: @head_timeout
      ]
  end

  defp reply(socket, status, reason, headers \\ []) do
    lines = Enum.map(headers ++ [{"content-length", "0"}], fn {k, v} -> [k, ": ", v, "\r\n"] end)
    data = ["HTTP/1.1 ", Integer.to_string(status), " ", reason, "\r\n", lines, "\r\n"]

    case socket do
      %Socket{} -> Socket.send(socket, data)
      ssl -> :ssl.send(ssl, data)
    end
  end

  # The request log: who sent what where, and what the proxy did about it.
  # Never the headers, never a body. The host's handler writes the line.
  defp log_request(%Session{meta: meta}, head, host, decision) do
    {outcome, rule} =
      case decision do
        {:ok, nil} -> {:passthrough, nil}
        {:ok, rule} -> {:injected, rule}
        {:error, :denied} -> {:denied, nil}
      end

    :telemetry.execute([:managoat, :broker, :request], %{count: 1}, %{
      method: head.method,
      host: host,
      path: path_only(head),
      outcome: outcome,
      rule: rule,
      meta: meta
    })
  end

  # A request the injector refused. Both reasons are a `403` and a
  # `:denied` event; they differ in who has to fix it, so the operator's
  # one says so in a log line. The rule's name, never its credential.
  defp log_refused_request(session, head, host, reason) do
    case reason do
      {:unsafe_credential, rule, surface} ->
        Logger.warning(
          "broker: rule #{inspect(rule)} cannot be substituted into a request #{surface}: " <>
            "its credential holds a character that would break the request"
        )

      _ ->
        :ok
    end

    log_request(session, head, host, {:error, :denied})
  end

  # One event per connection the proxy decides about, whatever it decided,
  # so a failure ratio has a denominator. `:ok` is an origin reached and the
  # client told so; `:upstream_failed` is the `502` path (a name that does
  # not resolve, an origin that will not connect); `:denied` is the `403`
  # path (a host outside a `deny` session's rules, or one that resolves into
  # the operator's own network); `:unauthenticated` is the `407`, where
  # there is no session yet and so no host to name.
  defp connect_event(session, host, port, outcome) do
    :telemetry.execute([:managoat, :broker, :connect], %{count: 1}, %{
      host: host,
      port: port,
      outcome: outcome,
      meta: session_meta(session)
    })
  end

  defp session_meta(%Session{meta: meta}), do: meta
  defp session_meta(nil), do: %{}

  # The `path` a request event carries: the URL path, and nothing else.
  #
  # A query string is not safe to log. It can already hold a credential
  # nobody brokered — a signed URL is one in itself, and an API key in
  # `?key=` is a shape clients use — so the invariant that no credential
  # reaches a host's log cannot wait on what the proxy substitutes. Both
  # request paths converge here and both drop the query and any fragment:
  # absolute-form targets arrive as `http://host/path?query`, and
  # origin-form ones from inside a tunnel as `/path?query`. The origin is
  # sent the target unchanged; only the event is narrowed.
  #
  # `CONNECT` names an authority, not a path, and an authority has no query
  # to leak, so it is reported as it was sent.
  defp path_only(%{method: "CONNECT", target: target}), do: target
  defp path_only(%{target: "http://" <> _ = target}), do: URI.parse(target).path || "/"

  defp path_only(%{target: target}) do
    target |> String.split(["?", "#"], parts: 2) |> hd()
  end
end
