defmodule Managoat.Broker.BodyLimitsTest do
  # The two body caps, end to end. Defaults match Agent Vault's — 1 GiB for
  # a request, none for a response — so a consumer that names neither gets
  # the behaviour it had.
  use Managoat.Broker.ProxyCase, async: true

  describe "the request cap" do
    setup do
      ctx = start_rig(max_request_bytes: 16)
      session = bearer_session("ghp_real")
      Map.merge(ctx, %{token: put_session(ctx, session), session: session})
    end

    test "a declared length over the cap is refused before the origin is told", ctx do
      tls = tunnel(ctx, ctx.token)

      :ok =
        :ssl.send(
          tls,
          "POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Length: 64\r\n\r\n"
        )

      {:ok, reply} = :ssl.recv(tls, 0, 5_000)
      assert reply =~ "HTTP/1.1 413"

      # Nothing was forwarded, so the origin never saw a request whose body
      # would never arrive. The next tunnel proves the listener is fine.
      tls = tunnel(ctx, ctx.token)
      {_, echoed} = request(tls, "GET /after HTTP/1.1\r\nHost: localhost\r\n\r\n")
      assert echoed["path"] == "/after"
    end

    test "a body at the cap is forwarded", ctx do
      tls = tunnel(ctx, ctx.token)
      body = String.duplicate("x", 16)

      {_, echoed} =
        request(
          tls,
          "POST /ok HTTP/1.1\r\nHost: localhost\r\nContent-Length: 16\r\n\r\n" <> body
        )

      assert echoed["body"] == body
    end

    test "a chunked body that passes the cap while streaming stops", ctx do
      # Chunked declares no length, so the cap is enforced as it streams.
      tls = tunnel(ctx, ctx.token)

      :ok =
        :ssl.send(
          tls,
          "POST /chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n" <>
            "10\r\n0123456789abcdef\r\n10\r\nfedcba9876543210\r\n0\r\n\r\n"
        )

      # The connection ends rather than the request completing: the origin
      # already has a partial body, so there is nothing honest to say to
      # the client and nothing to leave the socket open for.
      assert {:error, :closed} = :ssl.recv(tls, 0, 5_000)
    end

    test "an absolute-form request over the cap is 413", ctx do
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

      :ok =
        :gen_tcp.send(
          tcp,
          "POST http://localhost:#{ctx.http_port}/big HTTP/1.1\r\nHost: localhost\r\n" <>
            "Proxy-Authorization: #{proxy_auth(ctx.token)}\r\nContent-Length: 64\r\n\r\n"
        )

      assert read_until_closed(tcp) =~ "HTTP/1.1 413"
    end

    test "the refusal emits one terminal event with status 413", ctx do
      session = attach_request_telemetry(ctx)
      Memory.put(ctx.store, ctx.token, session)

      tls = tunnel(ctx, ctx.token)

      :ok =
        :ssl.send(tls, "POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Length: 64\r\n\r\n")

      {:ok, _} = :ssl.recv(tls, 0, 5_000)

      assert_receive {:request, %{count: 1, duration: _},
                      %{path: "/big", status: 413, outcome: :denied, error: nil}}

      refute_receive {:request, _, _}, 100
    end
  end

  describe "the request cap's default" do
    test "a consumer that names no cap gets 1 GiB, so ordinary bodies are unaffected" do
      ctx = start_rig()
      token = put_session(ctx, bearer_session("ghp_real"))
      tls = tunnel(ctx, token)
      body = String.duplicate("y", 4096)

      {_, echoed} =
        request(
          tls,
          "POST /default HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4096\r\n\r\n" <> body
        )

      assert echoed["body"] == body
    end
  end

  describe "the response cap" do
    test "an over-long response ends the connection and emits response_too_large" do
      ctx = start_rig(max_response_bytes: 8)
      session = bearer_session("ghp_real")
      ctx = Map.merge(ctx, %{token: put_session(ctx, session), session: session})
      Memory.put(ctx.store, ctx.token, attach_request_telemetry(ctx))

      tls = tunnel(ctx, ctx.token)

      # The origin echoes a JSON body well over eight bytes.
      :ok = :ssl.send(tls, "GET /long HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert_receive {:request, %{duration: _},
                      %{path: "/long", status: 200, error: :response_too_large}},
                     2_000
    end

    test "no cap is the default: a response of any size relays whole" do
      ctx = start_rig()
      token = put_session(ctx, bearer_session("ghp_real"))
      tls = tunnel(ctx, token)

      {_, echoed} = request(tls, "GET /uncapped HTTP/1.1\r\nHost: localhost\r\n\r\n")
      assert echoed["path"] == "/uncapped"
    end
  end
end
