defmodule Managoat.Broker.HTTPOnlyTest do
  use Managoat.Broker.ProxyCase, async: true

  defmodule AuthorityStore do
    @behaviour Managoat.Broker.Store
    @impl true
    def lookup(store, token), do: Memory.lookup(store, token)
    @impl true
    def authorize(_store, authority, _request), do: Agent.get(authority, & &1)
  end

  setup do
    ctx = start_rig()
    session = bearer_session("managed-bearer") |> Map.put(:http_only, true)
    token = put_session(ctx, session)
    attach_request_telemetry(Map.merge(ctx, %{session: session, token: token}))
    Map.merge(ctx, %{session: session, token: token})
  end

  test "raw WebSocket upgrade is refused inside an existing CONNECT tunnel", ctx do
    tls = tunnel(ctx, ctx.token)
    {_, body} = request(tls, "GET /before HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert body["headers"]["authorization"] == "Bearer managed-bearer"

    :ok =
      :ssl.send(
        tls,
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" <>
          "Connection: Upgrade\r\nSec-WebSocket-Key: #{Base.encode64("0123456789abcdef")}\r\n" <>
          "Sec-WebSocket-Version: 13\r\n\r\n"
      )

    assert recv_until(tls, "\r\n\r\n") =~ "403 Forbidden"
    assert {:error, :closed} = :ssl.recv(tls, 0, 2_000)
    assert_receive {:request, _, %{status: 403, error: :protocol_upgrade}}
  end

  for headers <- [
        [{"Upgrade", "websocket"}],
        [{"Connection", "keep-alive, upgrade"}],
        [{"X-Ordinary", "value\r\nUpgrade: websocket\r\nConnection: upgrade"}],
        [{"Upgrade ", "websocket"}],
        [{"X-Name\r\nUpgrade", "websocket"}]
      ] do
    test "template-generated #{inspect(headers)} never reaches the origin", ctx do
      rules = [
        %Rule{
          pattern: "localhost",
          scheme: :custom,
          credential: %{},
          template: Map.new(unquote(Macro.escape(headers)))
        }
      ]

      Memory.put(ctx.store, ctx.token, %{ctx.session | rules: rules})
      {port, _listener} = raw_origin(ctx, :ssl)
      tls = tunnel(ctx, ctx.token, "localhost:#{port}")
      :ok = :ssl.send(tls, "GET /echo HTTP/1.1\r\nHost: localhost\r\n\r\n")
      assert recv_until(tls, "\r\n\r\n") =~ "403 Forbidden"
      assert_receive {:origin_closed, _}, 2_000
      refute_received {:origin_request, _, _}
    end
  end

  test "templates cannot turn copied body bytes into an unchecked next request", ctx do
    rules = [
      %Rule{
        pattern: "localhost",
        scheme: :custom,
        template: %{"Content-Length" => "0"},
        credential: %{}
      }
    ]

    Memory.put(ctx.store, ctx.token, %{ctx.session | rules: rules})
    {port, _} = raw_origin(ctx, :ssl)
    tls = tunnel(ctx, ctx.token, "localhost:#{port}")
    body = "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n"

    :ssl.send(
      tls,
      "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: #{byte_size(body)}\r\n\r\n" <>
        body
    )

    assert recv_until(tls, "\r\n\r\n") =~ "403 Forbidden"
    assert_receive {:origin_closed, _}, 2_000
    refute_received {:origin_request, _, _}
  end

  test "raw rejection happens before resolving credentials", ctx do
    # Memory has no authorize callback. An attempted lookup would return 503.
    Memory.put(ctx.store, ctx.token, %{ctx.session | authorization: "unresolvable"})
    tls = tunnel(ctx, ctx.token)
    :ok = :ssl.send(tls, "GET /echo HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n")
    assert recv_until(tls, "\r\n\r\n") =~ "403 Forbidden"
  end

  test "nested CONNECT cannot turn the intercepted tunnel into another protocol", ctx do
    tls = tunnel(ctx, ctx.token)
    :ok = :ssl.send(tls, "CONNECT localhost:443 HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert recv_until(tls, "\r\n\r\n") =~ "403 Forbidden"
  end

  test "substitution-generated upgrade is checked on the outgoing headers", ctx do
    rule = %Rule{
      pattern: "localhost",
      scheme: :substitute,
      placeholder: "__mode__",
      credential: "upgrade"
    }

    Memory.put(ctx.store, ctx.token, %{ctx.session | rules: [rule]})
    tls = tunnel(ctx, ctx.token)
    :ok = :ssl.send(tls, "GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: __mode__\r\n\r\n")
    assert recv_until(tls, "\r\n\r\n") =~ "403 Forbidden"
  end

  test "unexpected fragmented upstream 101 never reaches the sandbox", ctx do
    {port, _} = raw_origin(ctx, :ssl)
    tls = tunnel(ctx, ctx.token, "localhost:#{port}")
    :ok = :ssl.send(tls, "GET /echo HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert_receive {:origin_request, origin, wire}, 2_000
    assert wire =~ "managed-bearer"
    send(origin, {:reply, "HTTP/1.1 10"})
    assert_receive {:origin_sent, ^origin}
    assert {:error, :timeout} = :ssl.recv(tls, 0, 25)
    send(origin, {:reply, "1 Switching Protocols\r\nUpgrade: websocket\r\n\r\nopaque-frames"})
    assert {:error, :closed} = :ssl.recv(tls, 0, 2_000)
    assert_receive {:request, _, %{status: nil, error: :upstream_upgrade}}
    assert_receive {:origin_closed, ^origin}, 2_000
  end

  test "chunked HTTP streams and subsequent requests remain usable", ctx do
    tls = tunnel(ctx, ctx.token)
    name = "http_only_stream_#{System.unique_integer([:positive])}"

    :ok =
      :ssl.send(tls, "GET /stream HTTP/1.1\r\nHost: localhost\r\nX-Stream-Name: #{name}\r\n\r\n")

    assert recv_until(tls, "data: first") =~ "200"
    send(String.to_existing_atom(name), :continue)
    assert recv_until(tls, "0\r\n\r\n") =~ "data: second"
    {_, body} = request(tls, "GET /after HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert body["headers"]["authorization"] == "Bearer managed-bearer"
    :ssl.close(tls)
  end

  test "plain HTTP keeps alive and rejects upgrade on its next request", ctx do
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

    for _ <- 1..2 do
      :gen_tcp.send(tcp, plain_request(ctx, ctx.http_port, ""))
      {_, body} = read_plain_json(tcp)
      assert body["headers"]["authorization"] == "Bearer managed-bearer"
    end

    :gen_tcp.send(tcp, plain_request(ctx, ctx.http_port, "Upgrade: websocket\r\n"))
    assert read_until_closed(tcp) =~ "403 Forbidden"
  end

  test "plain HTTP rejects an upstream 101 after an informational response", ctx do
    {port, _} = raw_origin(ctx, :gen_tcp)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    :gen_tcp.send(tcp, plain_request(ctx, port, ""))
    assert_receive {:origin_request, origin, _}, 2_000

    send(
      origin,
      {:reply, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 101 Switching Protocols\r\n\r\nframes"}
    )

    wire = read_until_closed(tcp)
    assert wire == "HTTP/1.1 100 Continue\r\n\r\n"
    assert_receive {:request, _, %{status: nil, error: :upstream_upgrade}}
  end

  test "plain HTTP forwards informational and streamed responses correctly", ctx do
    {port, _} = raw_origin(ctx, :gen_tcp)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    :gen_tcp.send(tcp, plain_request(ctx, port, ""))
    assert_receive {:origin_request, origin, _}, 2_000

    send(
      origin,
      {:reply,
       "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n"}
    )

    assert_receive {:origin_sent, ^origin}
    {:ok, first} = :gen_tcp.recv(tcp, 0, 2_000)
    assert first =~ "103"
    # Continue only after the first bytes reached the client.
    send(origin, {:reply, "3\r\ntwo\r\n0\r\n\r\n"})
    wire = recv_plain_until(tcp, "0\r\n\r\n", first)
    assert wire =~ "200 OK"
    assert wire =~ "one"
    assert wire =~ "two"
    :gen_tcp.close(tcp)
  end

  test "upgrade rejection and durable authorization both hold without invalidation messages" do
    ctx = start_rig(store_module: AuthorityStore)
    session = %{bearer_session("fresh-managed") | http_only: true}
    authority = start_supervised!({Agent, fn -> {:ok, session.rules} end})
    token = put_session(ctx, %{session | authorization: authority})
    first = tunnel(ctx, token)
    second = tunnel(ctx, token)
    {_, body} = request(first, "GET /before HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert body["headers"]["authorization"] == "Bearer fresh-managed"
    :ssl.send(first, "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n")
    assert recv_until(first, "\r\n\r\n") =~ "403 Forbidden"
    assert {:error, :closed} = :ssl.recv(first, 0, 2_000)
    Agent.update(authority, fn _ -> {:error, :denied} end)
    :ssl.send(second, "GET /after-fence HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert recv_until(second, "\r\n\r\n") =~ "403 Forbidden"
    assert {:error, :closed} = :ssl.recv(second, 0, 2_000)
  end

  defp recv_plain_until(tcp, needle, acc) do
    if String.contains?(acc, needle) do
      acc
    else
      {:ok, bytes} = :gen_tcp.recv(tcp, 0, 2_000)
      recv_plain_until(tcp, needle, acc <> bytes)
    end
  end

  defp plain_request(ctx, port, headers),
    do:
      "GET http://localhost:#{port}/echo HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: #{proxy_auth(ctx.token)}\r\n#{headers}\r\n"

  defp raw_origin(ctx, transport) do
    opts = [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true]
    opts = if transport == :ssl, do: opts ++ ctx.origin_tls, else: opts
    {:ok, listener} = transport.listen(0, opts)
    {:ok, {_, port}} = if(transport == :ssl, do: :ssl, else: :inet).sockname(listener)
    owner = self()

    start_supervised!(
      {Task,
       fn ->
         socket = accept(transport, listener)
         raw_loop(transport, socket, owner)
       end},
      id: make_ref()
    )

    on_exit(fn -> transport.close(listener) end)
    {port, listener}
  end

  defp accept(:ssl, listener) do
    {:ok, socket} = :ssl.transport_accept(listener, 5_000)
    {:ok, socket} = :ssl.handshake(socket, 5_000)
    socket
  end

  defp accept(:gen_tcp, listener) do
    {:ok, socket} = :gen_tcp.accept(listener, 5_000)
    socket
  end

  defp raw_loop(transport, socket, owner) do
    :ok = if(transport == :ssl, do: :ssl, else: :inet).setopts(socket, active: :once)

    receive do
      {kind, ^socket, bytes} when kind in [:ssl, :tcp] ->
        send(owner, {:origin_request, self(), bytes})
        raw_loop(transport, socket, owner)

      {kind, ^socket} when kind in [:ssl_closed, :tcp_closed] ->
        send(owner, {:origin_closed, self()})

      {:reply, bytes} ->
        transport.send(socket, bytes)
        send(owner, {:origin_sent, self()})
        raw_loop(transport, socket, owner)
    end
  end
end
