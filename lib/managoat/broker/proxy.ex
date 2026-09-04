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

  Absolute-form requests keep the sandbox's connection alive: it may carry
  another, and each one is authenticated, validated, matched against the
  session's rules and given its own read deadline again, so the second
  request on a connection is decided exactly as the first was. The two
  hops' lifetimes are decided separately, which is what a proxy is
  supposed to do with a hop-by-hop header: the *origin* connection is this
  request's alone — dialed fresh, asked to close, closed after the
  response — so there is no pooled socket to be caught being closed
  underneath a request whose body has already been streamed away and
  cannot be sent again. The response head is re-emitted with this hop's
  own `Connection` rather than the origin's, which is the one place a
  response is not relayed byte for byte; its body still is. A connection
  ends after one request when the client asked it to, when it speaks
  HTTP/1.0, when the response ends only at the origin's close, or on any
  refusal.

  On `CONNECT` the proxy opens the upstream TLS connection first (a host it
  cannot reach is a `502` before the tunnel exists), answers `200`, then
  completes a TLS handshake with the *sandbox* using a leaf for that host
  signed by the listener's `Managoat.Broker.CA`, which the sandbox trusts
  because the host installed the root. Inside the tunnel it reads each
  request head, lets `Managoat.Broker.Injector` rewrite the headers and the
  request target, and forwards the head and body to the origin. Bytes
  coming back are relayed untouched, so a streaming model reply streams.

  They are also framed. `Managoat.Broker.Response` watches the same bytes
  *after* they have gone to the sandbox and works out which request each
  response belongs to, what status it carried and when it ended. Framing is
  therefore never in the relay's way: it cannot delay or buffer a body, and
  when it fails the cost is telemetry rather than the response.

  Every request the proxy decides about emits `[:managoat, :broker,
  :request]` with `%{count: 1, duration: native}` and the metadata
  `method`, `host`, `path`, `outcome` (`:injected`, `:passthrough` or
  `:denied`), `rule` (the matched rule's name or nil), `status`, `error`
  and `meta` (the session's, unchanged). Never a header, never a body, and
  `path` is the URL path only — never a query string or a fragment, on
  either request path, because a query can carry a credential the proxy
  never saw. The origin still receives the target unchanged. The host
  attaches a handler and writes its log line.

  The event is **terminal**: exactly one per request, emitted when the
  request is over. An upstream response emits when its body completes or
  fails, carrying the origin's status and a monotonic `duration` that spans
  the whole request through the end of the response body. A refusal the
  proxy makes itself emits at once, with the status the proxy sent. `error`
  is nil on a completed request and otherwise names why it did not
  complete; a response whose head arrived and whose body then failed
  carries both. So a long-lived stream is not recorded until it ends.

  A refusal is a `403` — the session may not reach this host, or a
  credential could not be written where its placeholder sat — except for a
  matched rule whose credential the host never supplied, which is a `502`
  with `error: :credential_missing`: the broker failed to obtain a
  credential rather than deciding anything, and an agent should retry once
  it is provisioned. Inside a tunnel that `502` refuses the request without
  ending the tunnel, where the refused request left no body behind it.

  Beside it, every connection the proxy decides about emits `[:managoat,
  :broker, :connect]` with `%{count: 1}` and the metadata `host`, `port`,
  `outcome` (`:ok`, `:upstream_failed`, `:denied` or `:unauthenticated`)
  and `meta`. That event is emitted on every path, the ones that never
  reach an origin included, so "how much of this broker's egress is
  failing" is a ratio over it rather than a count with no denominator. On
  `:unauthenticated` there is no session and no destination yet, so `host`
  and `port` are nil and `meta` is empty.

  It counts *origin* connections, not sandbox ones. A `CONNECT` tunnel is
  one of each, but an absolute-form connection carrying three requests
  dials three times and emits three, since each request is its own
  decision about its own origin.

  ## Timeouts

  Three bound a connection, and one bounds a request. `@head_timeout` (30s)
  is how long the proxy waits for a client to begin a request;
  `@idle_timeout` (300s) is the gap it allows between reads, on the way in
  and on the way back; `@connect_timeout` (10s) is the upstream dial. All
  three are per operation, so none of them bounds a client that keeps
  sending — one byte at a time, forever.

  `request_read_timeout` does: it is a wall-clock deadline on reading one
  request, head and body, starting with that request's first byte. A read
  that would outlast it is cut short, the request is refused with `408`
  where there is still a client to tell, and the connection closes. It
  defaults to five minutes and a host can name its own, because it is the
  only bound here that can refuse a *valid* request: a large upload over a
  slow link is legitimate and slow. The response side is deliberately
  outside it — a `git clone` or an SSE stream runs long on the way back,
  which is the traffic this proxy exists for — as are WebSocket frames
  after an upgrade, which are no longer a request being read.

  This module is a `ThousandIsland.Handler`; ThousandIsland calls its
  `child_spec/1` for every accepted connection, which is why the listener's
  own child spec lives on `Managoat.Broker` and not here.
  """

  use ThousandIsland.Handler

  require Logger

  alias Managoat.Broker.{Certs, HTTP, Injector, Response, Session, Store}
  alias ThousandIsland.Socket

  @head_timeout 30_000
  @idle_timeout 300_000
  @connect_timeout 10_000

  # A response head this long has not arrived and is not going to be one.
  # The same bound `Managoat.Broker.Response` puts on the same bytes.
  @max_response_head 64 * 1024

  # Response headers that describe the hop they arrived on rather than the
  # response, so the proxy answers for its own hop instead of relaying
  # theirs.
  @hop_by_hop_response ~w(connection keep-alive proxy-connection)

  # The default wall-clock bound on reading *one* request, head and body,
  # overridable per listener with `request_read_timeout`. The two timeouts
  # above are per `recv`, so they bound the gap between reads and not the
  # read: a client sending one byte every four minutes never tripped either,
  # and at that rate the default 1 GiB body cap is reached in roughly eight
  # thousand years. The cap bounds volume; this bounds time.
  #
  # It is the one timeout here that can refuse a *valid* request — a large
  # upload over a slow link is a legitimate request that takes a long time —
  # which is why it is the one a host can name. The response side is
  # deliberately not bounded by it: a `git clone` or an SSE stream runs long
  # on the way back, and that is the traffic this proxy exists for.
  @request_read_timeout 300_000

  # How long the handler waits for the relay to emit the terminal events
  # for requests that never got an answer. A telemetry event is not worth
  # hanging a connection teardown on.
  @relay_stop_timeout 1_000

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
      upstream_ssl_options: Keyword.get(opts, :upstream_ssl_options, []),
      max_request_bytes: Keyword.get(opts, :max_request_bytes, 1024 * 1024 * 1024),
      max_response_bytes: Keyword.get(opts, :max_response_bytes, :infinity),
      request_read_timeout: Keyword.get(opts, :request_read_timeout, @request_read_timeout)
    }

    serve_client(socket, "", state, @auth_attempts)
  end

  # One request head off this connection, and what the proxy does about it.
  # Recurses only on `{:retry, _}`, which is a client coming back with a
  # credential after a `407`; every other outcome ends the connection.
  defp serve_client(socket, buffer, state, attempts) do
    with {:ok, head, rest, deadline} <- read_head(socket, buffer, nil, state),
         {:ok, session} <- authenticate(socket, head, rest, attempts, state),
         {:ok, {host, port}, target} <- destination(socket, head) do
      case head.method do
        "CONNECT" ->
          if reachable?(session, host, port) do
            tunnel(socket, host, port, session, state)
          else
            refuse_request(session, head, host, :denied)
            connect_event(session, host, port, :denied)
            reply(socket, 403, "Forbidden")
            {:close, state}
          end

        _ ->
          case forward_plain(socket, head, rest, {host, port, target}, session, state, deadline) do
            # Another absolute-form request on the same connection: read it
            # like the first. Which means it is authenticated, validated,
            # matched against the session's rules and given its own read
            # deadline again — none of that is carried over, and the second
            # request on a connection is decided exactly as the first was.
            {:keep_alive, rest} -> serve_client(socket, rest, state, attempts)
            {:close, _} = done -> done
          end
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

  # The head, and the deadline the rest of this request is read under. The
  # deadline starts with the request's first byte rather than with the
  # connection: waiting for a client to send anything at all is idle time,
  # bounded by `@head_timeout`, and a proxy connection held open between
  # requests is doing what a proxy connection is for.
  #
  # There is no session here — authentication reads this head — so an
  # expiry is answered and closed without a request event. There is nothing
  # to attribute one to, as on any unauthenticated connection.
  defp read_head(socket, buffer, deadline, state) do
    deadline = started(buffer, deadline, state.request_read_timeout)

    case HTTP.parse_request(buffer) do
      {:ok, head, rest} ->
        {:ok, head, rest, deadline}

      {:error, reason} ->
        reply(socket, 400, "Bad Request")
        {:error, reason}

      {:more, _} ->
        case recv_bounded(&Socket.recv(socket, 0, &1), deadline, @head_timeout) do
          {:ok, data} ->
            read_head(socket, buffer <> data, deadline, state)

          {:error, :request_timeout} ->
            reply(socket, 408, "Request Timeout")
            {:error, :request_timeout}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  # When the request being read has to be finished by. `nil` until its first
  # byte arrives, and `nil` for good when the host turned the bound off.
  defp started(_buffer, deadline, _timeout) when not is_nil(deadline), do: deadline
  defp started(_buffer, _deadline, :infinity), do: nil
  defp started("", _deadline, _timeout), do: nil

  defp started(_buffer, _deadline, timeout),
    do: System.monotonic_time(:millisecond) + timeout

  # One read, bounded by the request deadline as well as by the idle window
  # that would have applied anyway. `recv` takes the timeout to use, so the
  # three call sites keep their own socket and their own module.
  #
  # A read the deadline shortened comes back as `{:error, :timeout}` like
  # any other, so the deadline is checked again before that is believed:
  # otherwise the one thing this exists to report would be reported as a
  # stalled client.
  defp recv_bounded(recv, nil, idle), do: recv.(idle)

  defp recv_bounded(recv, deadline, idle) do
    case recv.(recv_window(deadline, idle)) do
      {:error, :timeout} -> timed_out(deadline)
      other -> other
    end
  end

  # Which of the two windows just closed. Only the deadline is worth a
  # name: an idle client is reported as one, as it always was.
  defp timed_out(deadline) do
    if deadline - System.monotonic_time(:millisecond) <= 0,
      do: {:error, :request_timeout},
      else: {:error, :timeout}
  end

  # How long the next read may block: never past the deadline, never longer
  # than the idle window that would have applied anyway. Zero once the
  # deadline has passed, which makes that read a poll that returns at once
  # and lands on `timed_out/1` with the answer.
  defp recv_window(deadline, idle) do
    deadline
    |> Kernel.-(System.monotonic_time(:millisecond))
    |> min(idle)
    |> max(0)
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
    with {:ok, addresses} <- resolve(socket, host, port, state),
         {:ok, upstream} <- connect_tls(socket, addresses, host, port, state) do
      Socket.send(socket, "HTTP/1.1 200 Connection established\r\n\r\n")
      connect_event(session, host, port, :ok)

      # The handshake runs on the raw socket: the handler is synchronous
      # from here to the end of the tunnel, so the transport switch stays
      # ours. (`Socket.upgrade` does not compose with a synchronous handler.)
      # Closing the TLS socket closes the TCP one under it, and the
      # handler's own close afterwards is a no-op on a closed port.
      case :ssl.handshake(socket.socket, client_ssl_options(state.certs, host), @head_timeout) do
        {:ok, client} ->
          # The relay owns the upstream socket's inbound side, so it can
          # wait on origin bytes and on the descriptors `serve/6` sends it
          # in one `receive`. It also owns every terminal event for a
          # forwarded request, including the ones this connection never
          # gets an answer to: `stop_relay/2` tells it why.
          relay =
            spawn_link(fn -> relay(upstream, client, Response.new(state.max_response_bytes)) end)

          :ok = :ssl.controlling_process(upstream, relay)
          :ok = :ssl.setopts(upstream, active: :once)

          # Everything about this tunnel that does not change per request,
          # gathered once so the per-request functions take what varies.
          conn = %{
            client: client,
            upstream: upstream,
            host: host,
            port: port,
            session: session,
            relay: relay,
            max_request_bytes: state.max_request_bytes,
            request_read_timeout: state.request_read_timeout
          }

          reason = serve(conn, "")

          stop_relay(relay, reason)
          :ssl.close(upstream)
          :ssl.close(client)
          {:close, state}

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

  # The origin's addresses, vetted. A sandbox may name any host, and the
  # proxy sits on the operator's network, so a name that resolves into a
  # private, loopback or link-local range is refused before any connection
  # exists: otherwise the broker is a door from a third-party sandbox into
  # the operator's network. The connection is then made to a vetted
  # address, not the name, so a rebinding DNS answer between check and dial
  # changes nothing. Off only for a test rig
  # (`allow_private_upstreams: true`), whose origins are on localhost.
  #
  # **Every** answer is vetted, and one blocked answer refuses the host.
  # Checking only the address about to be dialed would make the refusal
  # depend on resolver ordering, so a host with one public and one private
  # answer would be refused or allowed by luck. This is the rule Agent
  # Vault used.
  #
  # Both families are asked for, and the vetted list is returned in the
  # order they will be dialed: IPv4 first, then IPv6. That order is
  # deliberate — every host that worked before still takes the address it
  # took before, and IPv6 is a path for hosts that previously had none.
  defp resolve(socket, host, port, state) do
    case addresses(host) do
      [] ->
        Logger.info("broker: upstream #{host}:#{port} did not resolve")
        reply(socket, 502, "Bad Gateway")
        {:error, :nxdomain}

      addresses ->
        case blocked(addresses) do
          [first | _] when not state.allow_private_upstreams ->
            Logger.info("broker: refused #{host}:#{port}: resolves to #{:inet.ntoa(first)}")
            reply(socket, 403, "Forbidden")
            {:error, :private_upstream}

          _ ->
            {:ok, addresses}
        end
    end
  end

  @doc """
  Which of `addresses` the proxy must not dial on a sandbox's behalf.
  Pairs with `addresses/1`.

  Empty means the host may be reached. A non-empty result is a refusal of
  the *host*, whichever address was about to be dialed: checking only the
  one chosen would make the answer depend on resolver ordering, so a name
  with one public and one private answer would be refused or allowed by
  luck. Refusing on any blocked answer is the conservative rule, and the
  one Agent Vault used.
  """
  @spec blocked([:inet.ip_address()]) :: [:inet.ip_address()]
  def blocked(addresses), do: Enum.filter(addresses, &private?/1)

  @doc """
  Every address `host` resolves to, in the order the proxy would dial
  them, or `[]` when it does not resolve.

  A and AAAA are both asked for. A family that does not answer is not an
  error — most hosts have only one — so only the empty union means the
  name failed. IPv4 comes first: every host that resolved before this
  proxy spoke IPv6 still takes the address it took then, and IPv6 is a
  path for hosts that previously had none.

  The pair with `blocked/1` is the whole guard: `blocked(addresses(host))`
  empty means the host may be dialed.
  """
  @spec addresses(String.t()) :: [:inet.ip_address()]
  def addresses(host) do
    name = String.to_charlist(host)

    Enum.uniq(family_addresses(name, :inet) ++ family_addresses(name, :inet6))
  end

  defp family_addresses(name, family) do
    case :inet.getaddrs(name, family) do
      {:ok, addresses} -> addresses
      {:error, _} -> []
    end
  end

  # Each vetted address in turn, so a host whose first address will not
  # take a connection still reaches one that will. The reason reported is
  # the last one's, since that is the attempt that finally failed.
  defp connect_any([address], dial), do: dial.(address)

  defp connect_any([address | rest], dial) do
    case dial.(address) do
      {:ok, _} = ok -> ok
      {:error, _} -> connect_any(rest, dial)
    end
  end

  @doc """
  Is this an address the proxy must not dial on a sandbox's behalf?

  IPv4: RFC 1918, loopback, link-local (including the cloud metadata
  address), CGNAT, and the unspecified address.

  IPv6 is the same policy, and it has to be, or adding AAAA resolution
  would hand a sandbox every private range back through a second address
  family. Refused are the unspecified address, loopback, link-local
  (`fe80::/10`), the deprecated site-local prefix (`fec0::/10`),
  unique-local (`fc00::/7`), multicast (`ff00::/8`), the documentation
  prefix (`2001:db8::/32`) and the discard prefix (`100::/64`).

  The forms that *embed* an IPv4 address are decoded and run through the
  IPv4 policy rather than judged on their own, because otherwise each is a
  spelling of a blocked address that this function would call public:
  IPv4-mapped (`::ffff:169.254.169.254`), IPv4-compatible (`::169.254.
  169.254`), 6to4 (`2002:a9fe:a9fe::`) and the NAT64 well-known prefix
  (`64:ff9b::169.254.169.254`) all reach the cloud metadata service.
  """
  @spec private?(:inet.ip_address()) :: boolean()
  def private?({10, _, _, _}), do: true
  def private?({127, _, _, _}), do: true
  def private?({169, 254, _, _}), do: true
  def private?({172, b, _, _}) when b in 16..31, do: true
  def private?({192, 168, _, _}), do: true
  def private?({100, b, _, _}) when b in 64..127, do: true
  def private?({0, _, _, _}), do: true

  # An IPv6 address carrying an IPv4 one. These come first: they are
  # spellings of an IPv4 address, and the IPv4 policy is what decides them.
  # `::` and `::1` fall out of the IPv4-compatible clause, since `0.0.0.0`
  # and `0.0.0.1` are both refused by the rules above.
  def private?({0, 0, 0, 0, 0, 0xFFFF, hi, lo}), do: private?(embedded_v4(hi, lo))
  def private?({0, 0, 0, 0, 0, 0, hi, lo}), do: private?(embedded_v4(hi, lo))
  def private?({0x2002, hi, lo, _, _, _, _, _}), do: private?(embedded_v4(hi, lo))
  def private?({0x64, 0xFF9B, 0, 0, 0, 0, hi, lo}), do: private?(embedded_v4(hi, lo))

  # Ranges, as the first 16-bit group: fe80::/10, fc00::/7, ff00::/8.
  def private?({a, _, _, _, _, _, _, _}) when a in 0xFE80..0xFEBF, do: true
  def private?({a, _, _, _, _, _, _, _}) when a in 0xFEC0..0xFEFF, do: true
  def private?({a, _, _, _, _, _, _, _}) when a in 0xFC00..0xFDFF, do: true
  def private?({a, _, _, _, _, _, _, _}) when a in 0xFF00..0xFFFF, do: true
  def private?({0x2001, 0xDB8, _, _, _, _, _, _}), do: true
  def private?({0x100, 0, 0, 0, _, _, _, _}), do: true

  def private?(_), do: false

  # Two 16-bit groups back into the four octets they spell.
  defp embedded_v4(hi, lo), do: {div(hi, 256), rem(hi, 256), div(lo, 256), rem(lo, 256)}

  defp connect_tls(socket, addresses, host, port, state) do
    dial = fn address ->
      :ssl.connect(address, port, upstream_ssl_options(host, address, state), @connect_timeout)
    end

    case connect_any(addresses, dial) do
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
  # Origin → sandbox. Every byte is written to the sandbox the instant it
  # arrives; only then are the same bytes shown to `Managoat.Broker.
  # Response`, which says nothing about what to relay and only works out
  # which request just ended, with what status. So framing cannot delay,
  # reorder or buffer a body — a streaming reply streams exactly as it did
  # before it was framed — and a framing failure costs telemetry rather
  # than the response.
  #
  # The upstream socket is in `active: :once` here, which is what lets one
  # `receive` serve both origin bytes and the descriptors `serve/7` sends.
  defp relay(upstream, client, framer) do
    receive do
      {:expect, request} ->
        relay(upstream, client, Response.expect(framer, request))

      {:ssl, ^upstream, data} ->
        :ssl.setopts(upstream, active: :once)

        case :ssl.send(client, data) do
          :ok ->
            {framer, finished} = Response.observe(framer, data)
            Enum.each(finished, &emit_finished/1)

            # A response past its cap has already emitted; closing the
            # sandbox's side is what tells it the stream ended badly.
            if Response.halted?(framer) do
              :ssl.close(client)
              :ok
            else
              relay(upstream, client, framer)
            end

          {:error, _} ->
            finish_relay(framer, &Response.failed(&1, :client_closed))
        end

      {:ssl_closed, ^upstream} ->
        :ssl.close(client)
        finish_relay(framer, &Response.closed/1)

      {:ssl_error, ^upstream, _reason} ->
        :ssl.close(client)
        finish_relay(framer, &Response.failed(&1, :upstream_read_failed))

      {:stop, from, ref, reason} ->
        finish_relay(framer, &Response.failed(&1, reason))
        send(from, {:relay_stopped, ref})
    end
  end

  defp finish_relay(framer, fun) do
    {_framer, finished} = fun.(framer)
    Enum.each(finished, &emit_finished/1)
    :ok
  end

  # The handler is leaving. Anything the relay is still holding never got
  # its answer, and has to say so before the process goes away with the
  # link. Bounded, because a terminal event is not worth hanging a
  # connection teardown on.
  defp stop_relay(relay, reason) do
    # The monitor is not belt and braces: the relay ends itself when the
    # origin closes, which is the common case, and waiting for a reply from
    # a process that already finished would put the stop timeout on every
    # ordinary teardown.
    ref = Process.monitor(relay)
    send(relay, {:stop, self(), ref, reason})

    receive do
      {:relay_stopped, ^ref} -> Process.demonitor(ref, [:flush])
      {:DOWN, ^ref, :process, ^relay, _} -> :ok
    after
      @relay_stop_timeout -> Process.demonitor(ref, [:flush])
    end

    :ok
  end

  # Sandbox → upstream, one request at a time: head rewritten, body copied.
  # Returns why the loop ended, which is the reason any request still
  # awaiting a response gets.
  defp serve(conn, buffer), do: serve(conn, buffer, nil)

  defp serve(conn, buffer, deadline) do
    deadline = started(buffer, deadline, conn.request_read_timeout)

    case HTTP.parse_request(buffer) do
      {:ok, head, rest} ->
        framing = HTTP.body_framing(head)

        if declared_too_large?(framing, conn.max_request_bytes) do
          # A declared length over the cap is refused before the origin is
          # told anything, so the request never half-arrives there.
          refuse_request(conn.session, head, conn.host, :request_too_large)
          reply(conn.client, 413, "Content Too Large", [{"connection", "close"}])
          :client_closed
        else
          serve_injected(conn, head, rest, framing, deadline)
        end

      {:more, _} ->
        case recv_bounded(&:ssl.recv(conn.client, 0, &1), deadline, @idle_timeout) do
          {:ok, data} ->
            serve(conn, buffer <> data, deadline)

          # A head that never finished. There is a session and a
          # destination but no method and no path, so the event carries
          # what is known and leaves the rest nil — one terminal event, as
          # every refusal gets.
          {:error, :request_timeout} ->
            conn.session
            |> pending_request(%{method: nil, target: nil}, conn.host, {:error, :denied})
            |> emit(408, :request_timeout)

            reply(conn.client, 408, "Request Timeout", [{"connection", "close"}])
            :client_closed

          {:error, _} ->
            :client_closed
        end

      {:error, _} ->
        reply(conn.client, 400, "Bad Request", [{"connection", "close"}])
        :client_closed
    end
  end

  defp serve_injected(conn, head, rest, framing, deadline) do
    case Injector.inject(head.headers, conn.host, conn.port, head.target, conn.session) do
      {:ok, headers, target, rule} ->
        # `head` is the target the client sent; `target` is the one to
        # forward. Telemetry is derived from the former, so a substituted
        # credential is never what gets logged.
        request = pending_request(conn.session, head, conn.host, {:ok, rule})

        # Before the write, never after: an origin may answer faster than
        # the next line of code runs.
        send(conn.relay, {:expect, request})

        encoded = HTTP.encode_request(%{head | headers: headers}, target)

        with :ok <- :ssl.send(conn.upstream, encoded),
             {:ok, rest} <- copy_body(conn, framing, rest, deadline) do
          if upgrade?(head),
            do: pipe(conn.client, conn.upstream, rest),
            else: serve(conn, rest)
        else
          # The relay holds this request; it emits with the reason
          # `stop_relay/2` passes on. Nothing is written back for either of
          # these: the origin already holds a partial body, so there is
          # nothing honest left to say to the client.
          {:error, reason} when reason in [:request_too_large, :request_timeout] -> reason
          {:error, _} -> :upstream_send_failed
        end

      {:error, reason} ->
        refuse_request(conn.session, head, conn.host, reason)
        refuse_in_tunnel(conn, rest, framing, reason)
    end
  end

  # A refusal written into an open tunnel. A `502` for a credential the
  # broker could not obtain is about this request and not this connection —
  # the next request on the tunnel may match a rule that is provisioned — so
  # the tunnel survives it, as long as the refused request left nothing
  # behind it in the stream. A request with a body did: the proxy is not
  # forwarding that body and will not read one it is refusing, so the
  # framing would be lost and the next head would be read out of the middle
  # of it.
  #
  # A denial is the other thing. `403` says this session may not reach here,
  # which the next request would only hear again, so it closes as before.
  defp refuse_in_tunnel(conn, rest, framing, reason) do
    status = refusal_status(reason)

    if status == 502 and bodyless?(framing) do
      reply(conn.client, 502, "Bad Gateway")
      serve(conn, rest)
    else
      reply(conn.client, status, status_reason(status), [{"connection", "close"}])
      :client_closed
    end
  end

  # Did this request leave anything after its head for the next read to trip
  # over? A declared length of zero is a body, and is no bytes.
  defp bodyless?(:none), do: true
  defp bodyless?({:length, 0}), do: true
  defp bodyless?(_framing), do: false

  # A body whose length the client declared, compared with the cap before
  # anything is forwarded. A chunked body declares nothing, so it is
  # counted as it streams instead — see `copy_body/5`.
  defp declared_too_large?({:length, n}, limit) when is_integer(limit), do: n > limit
  defp declared_too_large?(_framing, _limit), do: false

  defp within?(_count, :infinity), do: true
  defp within?(count, limit), do: count <= limit

  defp copy_body(conn, framing, buffer, deadline) do
    copy_body(conn, framing, buffer, deadline, 0)
  end

  # `count` is the bytes forwarded so far. For a chunked body those include
  # the chunk framing, which the proxy forwards verbatim, so the cap is
  # very slightly conservative — deliberately, since the alternative is
  # parsing a body this proxy has no business reading.
  #
  # The deadline is the other bound, and it is the one a drip trips: each
  # `recv` here is allowed to wait the idle window, so a client sending one
  # byte at a time never times out on any single read.
  defp copy_body(conn, framing, buffer, deadline, count) do
    case HTTP.take_body(framing, buffer) do
      {:done, bytes, rest} ->
        if within?(count + byte_size(bytes), conn.max_request_bytes) do
          send_upstream(conn.upstream, bytes)
          {:ok, rest}
        else
          {:error, :request_too_large}
        end

      {:partial, bytes, framing} ->
        count = count + byte_size(bytes)

        with true <- within?(count, conn.max_request_bytes),
             :ok <- send_upstream(conn.upstream, bytes),
             {:ok, data} <-
               recv_bounded(&:ssl.recv(conn.client, 0, &1), deadline, @idle_timeout) do
          copy_body(conn, framing, data, deadline, count)
        else
          false -> {:error, :request_too_large}
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
      _ -> :client_closed
    end
  end

  defp send_upstream(_upstream, ""), do: :ok
  defp send_upstream(upstream, bytes), do: :ssl.send(upstream, bytes)

  # ---------------------------------------------------------------------------
  # Absolute-form: one plain-HTTP request, its response, then close

  defp forward_plain(socket, head, rest, {host, port, target}, session, state, deadline) do
    framing = HTTP.body_framing(head)

    with false <- oversized_plain(socket, session, head, host, framing, state),
         {:ok, headers, target, rule} <-
           inject_or_deny(socket, head, host, port, target, session),
         {:ok, addresses} <- resolve(socket, host, port, state),
         {:ok, upstream} <- connect_plain(socket, addresses, host, port) do
      connect_event(session, host, port, :ok)

      plain = %{
        client: socket,
        upstream: upstream,
        max_request_bytes: state.max_request_bytes,
        max_response_bytes: state.max_response_bytes,
        pending: pending_request(session, head, host, {:ok, rule})
      }

      outcome = exchange_plain(plain, head, headers, target, rest, deadline)

      # The upstream connection belongs to this request and closes with it,
      # whatever the sandbox's connection goes on to do. See the moduledoc:
      # the two hops' lifetimes are decided separately, and only the
      # sandbox's is being kept.
      :gen_tcp.close(upstream)
      outcome_of(outcome, state)
    else
      true ->
        {:close, state}

      {:error, reason} when reason in [:denied, :private_upstream] ->
        connect_event(session, host, port, :denied)
        {:close, state}

      {:error, _} ->
        connect_event(session, host, port, :upstream_failed)
        {:close, state}
    end
  end

  defp outcome_of({:keep_alive, rest}, _state), do: {:keep_alive, rest}
  defp outcome_of(:close, state), do: {:close, state}

  # One absolute-form request and its response. `{:keep_alive, rest}` when
  # the sandbox's connection may carry another (`rest` is whatever it has
  # already sent of the next one), `:close` otherwise.
  defp exchange_plain(plain, head, headers, target, rest, deadline) do
    framer = Response.expect(Response.new(plain.max_response_bytes), plain.pending)

    # The origin is asked to close whatever the sandbox asked of us: this
    # request dials its own connection, so there is no pooled socket to
    # reuse and none to be caught being closed underneath a request whose
    # body has already been streamed away and cannot be sent again.
    upstream_headers = [
      {"connection", "close"}
      | Enum.reject(headers, &(String.downcase(elem(&1, 0)) == "connection"))
    ]

    encoded = HTTP.encode_request(%{head | headers: upstream_headers}, target)

    with :ok <- :gen_tcp.send(plain.upstream, encoded),
         {:ok, rest} <-
           copy_body_plain(
             plain.client,
             plain.upstream,
             HTTP.body_framing(head),
             {plain.max_request_bytes, deadline},
             rest
           ) do
      pump_plain(plain, framer, head, rest)
    else
      {:error, reason} when reason in [:request_too_large, :request_timeout] ->
        finish_relay(framer, &Response.failed(&1, reason))
        :close

      {:error, _} ->
        finish_relay(framer, &Response.failed(&1, :upstream_send_failed))
        :close
    end
  end

  # `true` when the request is refused for its size, having answered the
  # client. The `403` paths below return `{:error, _}`; this one is its own
  # shape so the `with` can tell them apart without inventing a reason
  # that means "already answered".
  defp oversized_plain(socket, session, head, host, framing, state) do
    if declared_too_large?(framing, state.max_request_bytes) do
      refuse_request(session, head, host, :request_too_large)
      connect_event(session, host, nil, :denied)
      reply(socket, 413, "Content Too Large")
      true
    else
      false
    end
  end

  defp inject_or_deny(socket, head, host, port, target, session) do
    case Injector.inject(head.headers, host, port, target, session) do
      {:ok, _, _, _} = ok ->
        ok

      {:error, reason} ->
        refuse_request(session, head, host, reason)
        status = refusal_status(reason)
        reply(socket, status, status_reason(status))
        {:error, :denied}
    end
  end

  defp connect_plain(socket, addresses, host, port) do
    dial = fn address ->
      :gen_tcp.connect(address, port, [:binary, family(address), active: false], @connect_timeout)
    end

    case connect_any(addresses, dial) do
      {:ok, _} = ok ->
        ok

      {:error, reason} ->
        Logger.info("broker: upstream #{host}:#{port} unreachable: #{inspect(reason)}")
        reply(socket, 502, "Bad Gateway")
        {:error, reason}
    end
  end

  # The socket has to be opened in the address's own family; an `:inet`
  # socket cannot dial an 8-tuple.
  defp family(address) when tuple_size(address) == 8, do: :inet6
  defp family(_address), do: :inet

  defp copy_body_plain(client, upstream, framing, bounds, buffer) do
    copy_body_plain(client, upstream, framing, bounds, buffer, 0)
  end

  # As `copy_body/5` inside a tunnel: the cap bounds how much of a body the
  # proxy will forward, the deadline how long it will spend reading one.
  defp copy_body_plain(client, upstream, framing, {limit, deadline} = bounds, buffer, count) do
    case HTTP.take_body(framing, buffer) do
      {:done, bytes, rest} ->
        if within?(count + byte_size(bytes), limit) do
          plain_send(upstream, bytes)
          {:ok, rest}
        else
          {:error, :request_too_large}
        end

      {:partial, bytes, framing} ->
        count = count + byte_size(bytes)

        with true <- within?(count, limit),
             :ok <- plain_send(upstream, bytes),
             {:ok, data} <- recv_bounded(&Socket.recv(client, 0, &1), deadline, @idle_timeout) do
          copy_body_plain(client, upstream, framing, bounds, data, count)
        else
          false -> {:error, :request_too_large}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp plain_send(_upstream, ""), do: :ok
  defp plain_send(upstream, bytes), do: :gen_tcp.send(upstream, bytes)

  # The response, back to the sandbox. The head is the one thing this path
  # cannot relay verbatim — `Connection` describes the hop it arrived on,
  # and the proxy is the one that asked the origin to close — so it is read
  # in full, re-emitted with this hop's own answer, and only then shown to
  # the framer. The body is untouched: every byte reaches the sandbox the
  # instant it arrives and the framer sees the same bytes afterwards,
  # exactly as before.
  defp pump_plain(plain, framer, request) do
    case read_response_head(plain.upstream, "") do
      {:ok, response, head_bytes, tail} ->
        keep? = keep_alive?(request, response)

        with :ok <- Socket.send(plain.client, rehead(response, keep?)),
             :ok <- client_send(plain.client, tail) do
          relay_plain(plain, observe(framer, head_bytes <> tail), keep?)
        else
          {:error, _} ->
            finish_relay(framer, &Response.failed(&1, :client_closed))
            :close
        end

      {:error, reason} ->
        finish_relay(framer, &Response.failed(&1, reason))
        :close
    end
  end

  defp pump_plain(plain, framer, request, client_rest) do
    case pump_plain(plain, framer, request) do
      {:keep_alive, _} -> {:keep_alive, client_rest}
      :close -> :close
    end
  end

  # The rest of the body, verbatim, until the framer says the response
  # ended. A response that ends only at the origin's close keeps this loop
  # running to the close, which is what says it ended.
  defp relay_plain(plain, framer, keep?) do
    cond do
      # A response past its cap has already emitted; nothing is left to
      # relay it to, and nothing this connection could honestly carry next.
      Response.halted?(framer) ->
        :close

      Response.idle?(framer) ->
        if keep?, do: {:keep_alive, nil}, else: :close

      true ->
        case :gen_tcp.recv(plain.upstream, 0, @idle_timeout) do
          {:ok, data} ->
            case Socket.send(plain.client, data) do
              :ok ->
                relay_plain(plain, observe(framer, data), keep?)

              {:error, _} ->
                finish_relay(framer, &Response.failed(&1, :client_closed))
                :close
            end

          {:error, :closed} ->
            finish_relay(framer, &Response.closed/1)
            :close

          {:error, _} ->
            finish_relay(framer, &Response.failed(&1, :upstream_read_failed))
            :close
        end
    end
  end

  defp observe(framer, data) do
    {framer, finished} = Response.observe(framer, data)
    Enum.each(finished, &emit_finished/1)
    framer
  end

  # A response head, in full, before any of it reaches the sandbox. Bounded
  # for the reason `Managoat.Broker.Response` bounds an incomplete head by
  # the same 64 KiB: the bytes of a head that has not arrived are the only
  # thing either of them holds on to, and a head this long is not going to
  # be one.
  defp read_response_head(upstream, buffer) do
    case HTTP.parse_response(buffer) do
      {:ok, response, rest} ->
        {:ok, response, binary_part(buffer, 0, byte_size(buffer) - byte_size(rest)), rest}

      {:more, _} when byte_size(buffer) > @max_response_head ->
        {:error, :malformed_response}

      {:more, _} ->
        case :gen_tcp.recv(upstream, 0, @idle_timeout) do
          {:ok, data} -> read_response_head(upstream, buffer <> data)
          {:error, :closed} -> {:error, :upstream_closed}
          {:error, _} -> {:error, :upstream_read_failed}
        end

      {:error, _reason} ->
        {:error, :malformed_response}
    end
  end

  # May the sandbox's connection carry another request? Everything has to
  # agree. The client asked for one, by speaking HTTP/1.1 and not saying
  # `close` — an HTTP/1.0 client is answered and closed, since keep-alive
  # was the exception there and negotiating it is not worth the ambiguity.
  # The response says exactly where it ends, because a body that runs to
  # the close cannot be followed by anything. And it is not an upgrade,
  # after which the bytes are no longer HTTP at all.
  defp keep_alive?(request, response) do
    request.version == {1, 1} and
      not close_requested?(request.headers) and
      response.status != 101 and
      HTTP.response_framing(response.status, response.headers, request.method) != :until_close
  end

  defp close_requested?(headers) do
    case HTTP.header(headers, "connection") do
      nil ->
        false

      value ->
        value
        |> String.downcase()
        |> String.split(",")
        |> Enum.map(&String.trim/1)
        |> Enum.member?("close")
    end
  end

  # The response head as this hop must present it. `Connection` and
  # `Keep-Alive` describe the hop they arrived on — the proxy asked the
  # origin to close, which is not the sandbox's business — so they are
  # replaced by what this hop is doing. `Transfer-Encoding` is hop-by-hop
  # too and deliberately stays: the body is relayed verbatim, chunk framing
  # included, so the header describing it has to survive with it.
  defp rehead(response, keep_alive?) do
    headers =
      response.headers
      |> Enum.reject(&(String.downcase(elem(&1, 0)) in @hop_by_hop_response))
      |> Kernel.++([{"connection", if(keep_alive?, do: "keep-alive", else: "close")}])

    HTTP.encode_response(%{response | headers: headers})
  end

  defp client_send(_client, ""), do: :ok
  defp client_send(client, bytes), do: Socket.send(client, bytes)

  # ---------------------------------------------------------------------------

  # A pure keyword list, so `Keyword.merge` with the host's options works.
  defp upstream_ssl_options(host, address, state) do
    [
      mode: :binary,
      active: false,
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)],
      alpn_advertised_protocols: ["http/1.1"],
      depth: 5
    ]
    |> Keyword.merge(sni(host))
    |> Keyword.merge(state.upstream_ssl_options)
    |> Kernel.++([family(address)])
  end

  # RFC 6066 has no name to put in SNI for an origin named by address and
  # forbids sending one, so the option is **omitted** for a literal —
  # never set to `:disable`, which turns hostname verification off
  # altogether: `:ssl` would then accept a certificate naming any address
  # at all. Omitted, `:ssl` falls back to the `Host` argument of
  # `connect/4`, which is the vetted address tuple, and verifies the
  # certificate's `iPAddress` SAN against it.
  #
  # For a name the option stays load-bearing, because the proxy dials the
  # vetted address rather than the name: without it `:ssl` would verify
  # the tuple against a certificate full of DNS names and refuse every
  # origin.
  defp sni(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, _address} -> []
      {:error, _} -> [server_name_indication: String.to_charlist(host)]
    end
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

  # What the proxy knows about a request while it waits for the answer:
  # everything the event will carry except the parts only the ending
  # supplies. Never the headers, never a body.
  defp pending_request(%Session{meta: meta}, head, host, decision) do
    {outcome, rule} =
      case decision do
        {:ok, nil} -> {:passthrough, nil}
        {:ok, rule} -> {:injected, rule}
        {:error, _} -> {:denied, nil}
      end

    %{
      method: head.method,
      host: host,
      path: path_only(head),
      outcome: outcome,
      rule: rule,
      meta: meta,
      started_at: System.monotonic_time()
    }
  end

  # A request the proxy answered itself. There is no upstream response to
  # wait for, so the event is terminal the moment the refusal is written,
  # and it carries the status the proxy sent.
  defp refuse_request(session, head, host, reason) do
    case reason do
      {:unusable_placeholder, rule} ->
        Logger.warning(
          "broker: rule #{inspect(rule)} has a placeholder that is not usable as one: " <>
            "it must be four characters or more, hold a letter or digit, and carry a " <>
            "boundary (`__` at either end, or a character outside [A-Za-z0-9_]). " <>
            "Without one it rewrites ordinary text in paths and header values."
        )

      {:unsafe_credential, rule, surface} ->
        Logger.warning(
          "broker: rule #{inspect(rule)} cannot be substituted into a request #{surface}: " <>
            "its credential holds a character that would break the request"
        )

      {:credential_missing, rule, scheme} ->
        Logger.warning(
          "broker: rule #{inspect(rule)} (#{inspect(scheme)}) has no usable credential, " <>
            "so the request was refused with 502 rather than sent without one. The session " <>
            "was built with the credential missing, undecryptable, or not yet granted."
        )

      _ ->
        :ok
    end

    session
    |> pending_request(head, host, {:error, :denied})
    |> emit(refusal_status(reason), refusal_error(reason))
  end

  # What the event's `error` names. A policy refusal has nothing to add —
  # `outcome: :denied` with the status is the whole story — but a `502` is
  # the broker failing rather than deciding, and a host reading its request
  # log has to be able to tell the two apart without parsing a message.
  defp refusal_error({:credential_missing, _rule, _scheme}), do: :credential_missing
  defp refusal_error(_reason), do: nil

  defp refusal_status(:request_too_large), do: 413
  defp refusal_status({:credential_missing, _rule, _scheme}), do: 502
  defp refusal_status(_reason), do: 403

  # The two a refused request can carry. A `413` is written where the size
  # is checked, which is before any of this.
  defp status_reason(403), do: "Forbidden"
  defp status_reason(502), do: "Bad Gateway"

  defp emit_finished({request, status, error}), do: emit(request, status, error)

  # The request log: who sent what where, what the proxy did about it, and
  # how it ended. One event per request, on every terminal path, with a
  # monotonic `duration` in native units beside `count` — a host converts
  # it to whatever unit it stores.
  defp emit(request, status, error) do
    :telemetry.execute(
      [:managoat, :broker, :request],
      %{count: 1, duration: System.monotonic_time() - request.started_at},
      %{
        method: request.method,
        host: request.host,
        path: request.path,
        outcome: request.outcome,
        rule: request.rule,
        status: status,
        error: error,
        meta: request.meta
      }
    )
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
  # A head that never finished has no target to narrow.
  defp path_only(%{target: nil}), do: nil
  defp path_only(%{method: "CONNECT", target: target}), do: target
  defp path_only(%{target: "http://" <> _ = target}), do: URI.parse(target).path || "/"

  defp path_only(%{target: target}) do
    target |> String.split(["?", "#"], parts: 2) |> hd()
  end
end
