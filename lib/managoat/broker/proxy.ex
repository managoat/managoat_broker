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

  alias Managoat.Broker.{Certs, HTTP, Injector, Response, Session, Store}
  alias ThousandIsland.Socket

  @head_timeout 30_000
  @idle_timeout 300_000
  @connect_timeout 10_000

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
            refuse_request(session, head, host, :denied)
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
          relay = spawn_link(fn -> relay(upstream, client, Response.new()) end)
          :ok = :ssl.controlling_process(upstream, relay)
          :ok = :ssl.setopts(upstream, active: :once)

          reason = serve(client, upstream, host, port, session, relay, "")
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

  Empty means the host may be reached. A non-empty result is a refusal of
  the *host*, whichever address was about to be dialed: checking only the
  one chosen would make the answer depend on resolver ordering, so a name
  with one public and one private answer would be refused or allowed by
  luck. Refusing on any blocked answer is the conservative rule, and the
  one Agent Vault used.
  """
  @spec blocked([:inet.ip_address()]) :: [:inet.ip_address()]
  def blocked(addresses), do: Enum.filter(addresses, &private?/1)

  # A and AAAA. A family that does not answer is not an error — most hosts
  # have only one — so only the empty union is a failure to resolve.
  defp addresses(host) do
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
            relay(upstream, client, framer)

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
  defp serve(client, upstream, host, port, session, relay, buffer) do
    case HTTP.parse_request(buffer) do
      {:ok, head, rest} ->
        case Injector.inject(head.headers, host, port, head.target, session) do
          {:ok, headers, target, rule} ->
            # `head` is the target the client sent; `target` is the one to
            # forward. Telemetry is derived from the former, so a
            # substituted credential is never what gets logged.
            request = pending_request(session, head, host, {:ok, rule})

            # Before the write, never after: an origin may answer faster
            # than the next line of code runs.
            send(relay, {:expect, request})

            encoded = HTTP.encode_request(%{head | headers: headers}, target)

            with :ok <- :ssl.send(upstream, encoded),
                 {:ok, rest} <- copy_body(client, upstream, HTTP.body_framing(head), rest) do
              if upgrade?(head),
                do: pipe(client, upstream, rest),
                else: serve(client, upstream, host, port, session, relay, rest)
            else
              # The relay holds this request; it emits with the reason
              # `stop_relay/2` passes on.
              {:error, _} -> :upstream_send_failed
            end

          {:error, reason} ->
            refuse_request(session, head, host, reason)
            reply(client, 403, "Forbidden", [{"connection", "close"}])
            :client_closed
        end

      {:more, _} ->
        case :ssl.recv(client, 0, @idle_timeout) do
          {:ok, data} -> serve(client, upstream, host, port, session, relay, buffer <> data)
          {:error, _} -> :client_closed
        end

      {:error, _} ->
        reply(client, 400, "Bad Request", [{"connection", "close"}])
        :client_closed
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
      _ -> :client_closed
    end
  end

  defp send_upstream(_upstream, ""), do: :ok
  defp send_upstream(upstream, bytes), do: :ssl.send(upstream, bytes)

  # ---------------------------------------------------------------------------
  # Absolute-form: one plain-HTTP request, its response, then close

  defp forward_plain(socket, head, rest, host, port, target, session, state) do
    with {:ok, headers, target, rule} <-
           inject_or_deny(socket, head, host, port, target, session),
         {:ok, addresses} <- resolve(socket, host, port, state),
         {:ok, upstream} <- connect_plain(socket, addresses, host, port) do
      connect_event(session, host, port, :ok)

      headers = [
        {"connection", "close"}
        | Enum.reject(headers, &(String.downcase(elem(&1, 0)) == "connection"))
      ]

      # One request, so the framer here is a queue of one and the handler
      # itself relays and frames; no second process to correlate with.
      framer = Response.expect(Response.new(), pending_request(session, head, host, {:ok, rule}))
      encoded = HTTP.encode_request(%{head | headers: headers}, target)

      with :ok <- :gen_tcp.send(upstream, encoded),
           :ok <- copy_body_plain(socket, upstream, HTTP.body_framing(head), rest) do
        pump_plain(upstream, socket, framer)
      else
        {:error, _} -> finish_relay(framer, &Response.failed(&1, :upstream_send_failed))
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
        refuse_request(session, head, host, reason)
        reply(socket, 403, "Forbidden")
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

  # As in a tunnel: every byte reaches the sandbox first, and the same
  # bytes are then shown to the framer, which only works out when the
  # response ended. The loop still runs to the origin's close — the proxy
  # sent `Connection: close`, so that is the end of the exchange — but the
  # event fires when the body completes, not when the socket does.
  defp pump_plain(upstream, client, framer) do
    case :gen_tcp.recv(upstream, 0, @idle_timeout) do
      {:ok, data} ->
        case Socket.send(client, data) do
          :ok ->
            {framer, finished} = Response.observe(framer, data)
            Enum.each(finished, &emit_finished/1)
            pump_plain(upstream, client, framer)

          {:error, _} ->
            finish_relay(framer, &Response.failed(&1, :client_closed))
        end

      {:error, :closed} ->
        finish_relay(framer, &Response.closed/1)

      {:error, _} ->
        finish_relay(framer, &Response.failed(&1, :upstream_read_failed))
    end
  end

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

  # RFC 6066 has no name to put in SNI for an origin named by address, and
  # forbids sending one; the certificate is matched against the address
  # itself instead. Appended after the merge rather than merged, because a
  # family is a bare atom and the list above stays a keyword list so a
  # host's own options can merge over it.
  defp sni(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, _address} -> [server_name_indication: :disable]
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
      {:unsafe_credential, rule, surface} ->
        Logger.warning(
          "broker: rule #{inspect(rule)} cannot be substituted into a request #{surface}: " <>
            "its credential holds a character that would break the request"
        )

      _ ->
        :ok
    end

    session
    |> pending_request(head, host, {:error, :denied})
    |> emit(403, nil)
  end

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
  defp path_only(%{method: "CONNECT", target: target}), do: target
  defp path_only(%{target: "http://" <> _ = target}), do: URI.parse(target).path || "/"

  defp path_only(%{target: target}) do
    target |> String.split(["?", "#"], parts: 2) |> hd()
  end
end
