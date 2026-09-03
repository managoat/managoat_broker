defmodule Managoat.Broker.ProxyTest do
  # The proxy end to end: a sandbox-shaped client dials the listener with a
  # session token, tunnels TLS to an origin, and the origin sees the real
  # credential where the client sent a placeholder.
  use Managoat.Broker.ProxyCase, async: true

  import ExUnit.CaptureLog

  alias Managoat.Broker.Proxy

  setup do
    ctx = start_rig()

    session = %Session{
      rules: [
        %Rule{name: "origin", pattern: "localhost", scheme: :bearer, credential: "ghp_real"}
      ],
      unmatched_host_policy: :passthrough,
      expires_at: DateTime.add(DateTime.utc_now(), 600, :second),
      meta: %{conversation_id: "conv-1", user_id: "user-1"}
    }

    Map.merge(ctx, %{token: put_session(ctx, session), session: session})
  end

  test "the origin sees the real credential where the sandbox sent a placeholder", ctx do
    tls = tunnel(ctx, ctx.token)

    {head, echoed} =
      request(
        tls,
        "GET /repos HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer __github_token__\r\n\r\n"
      )

    assert head =~ "HTTP/1.1 200"
    assert echoed["path"] == "/repos"
    assert echoed["headers"]["authorization"] == "Bearer ghp_real"
    refute Map.has_key?(echoed["headers"], "proxy-authorization")
  end

  test "several requests ride one tunnel, bodies included", ctx do
    tls = tunnel(ctx, ctx.token)

    {_, first} = request(tls, "GET /a HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert first["path"] == "/a"
    assert first["headers"]["authorization"] == "Bearer ghp_real"

    {_, second} =
      request(
        tls,
        "POST /b HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
      )

    assert second["method"] == "POST"
    assert second["body"] == "hello"

    {_, third} =
      request(
        tls,
        "POST /c HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
      )

    assert third["body"] == "abcde"
  end

  test "a request body that arrives in pieces is copied whole", ctx do
    tls = tunnel(ctx, ctx.token)
    :ok = :ssl.send(tls, "POST /p HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n0123")
    Process.sleep(50)
    :ok = :ssl.send(tls, "456789")
    {_, echoed} = read_response(tls, "")
    assert echoed["body"] == "0123456789"
  end

  test "a request head that arrives in pieces is parsed whole", ctx do
    tls = tunnel(ctx, ctx.token)
    :ok = :ssl.send(tls, "GET /split HTTP/1.1\r\nHost: loc")
    Process.sleep(50)
    :ok = :ssl.send(tls, "alhost\r\n\r\n")
    {_, echoed} = read_response(tls, "")
    assert echoed["path"] == "/split"
  end

  test "a wrong token, an expired session, garbage and no token are all 407", ctx do
    expired = %{ctx.session | expires_at: DateTime.add(DateTime.utc_now(), -1, :second)}
    expired_token = put_session(ctx, expired)

    for auth <- [
          proxy_auth("mb_nope"),
          proxy_auth(expired_token),
          "Basic " <> Base.encode64("garbage"),
          "Basic not-base64!",
          "Bearer #{ctx.token}",
          nil
        ] do
      {_tcp, reply} = connect(ctx, "localhost:#{ctx.https_port}", auth)
      assert reply =~ "HTTP/1.1 407", "#{inspect(auth)} was not refused"
      assert reply =~ ~r/proxy-authenticate: Basic/i
    end
  end

  test "the label half of the proxy credential is not checked: the token is the binding", ctx do
    {_tcp, reply} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(ctx.token, "other"))
    assert reply =~ "HTTP/1.1 200"
  end

  test "an origin the proxy cannot reach is a 502 before any tunnel exists", ctx do
    {_tcp, reply} = connect(ctx, "localhost:1", proxy_auth(ctx.token))
    assert reply =~ "HTTP/1.1 502"
  end

  test "a host that does not resolve is a 502", ctx do
    {_tcp, reply} = connect(ctx, "no-such-host.invalid:443", proxy_auth(ctx.token))
    assert reply =~ "HTTP/1.1 502"
  end

  test "a bad request line and a bad CONNECT authority are 400", ctx do
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    :ok = :gen_tcp.send(tcp, "\x16\x03\x01 not http\r\n\r\n")
    {:ok, reply} = :gen_tcp.recv(tcp, 0, 5_000)
    assert reply =~ "HTTP/1.1 400"

    {_tcp, reply} = connect(ctx, "nope", proxy_auth(ctx.token))
    assert reply =~ "HTTP/1.1 400"
  end

  test "an abandoned connection does not affect the listener", ctx do
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    :ok = :gen_tcp.close(tcp)

    {_tcp, reply} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(ctx.token))
    assert reply =~ "HTTP/1.1 200"
  end

  test "garbage inside an established tunnel is 400 and closes that tunnel", ctx do
    tls = tunnel(ctx, ctx.token)
    :ok = :ssl.send(tls, "not an HTTP request\r\n\r\n")
    {:ok, reply} = :ssl.recv(tls, 0, 5_000)
    assert reply =~ "HTTP/1.1 400"
  end

  test "an unreachable plain HTTP origin is 502", ctx do
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

    :ok =
      :gen_tcp.send(
        tcp,
        "GET http://localhost:1/ HTTP/1.1\r\nHost: localhost\r\n" <>
          "Proxy-Authorization: #{proxy_auth(ctx.token)}\r\n\r\n"
      )

    assert read_until_closed(tcp) =~ "HTTP/1.1 502"
  end

  test "closing a partial plain HTTP body does not affect later connections", ctx do
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

    :ok =
      :gen_tcp.send(
        tcp,
        "POST http://localhost:#{ctx.http_port}/body HTTP/1.1\r\nHost: localhost\r\n" <>
          "Proxy-Authorization: #{proxy_auth(ctx.token)}\r\nContent-Length: 10\r\n\r\nshort"
      )

    :ok = :gen_tcp.close(tcp)

    {_tcp, reply} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(ctx.token))
    assert reply =~ "HTTP/1.1 200"
  end

  test "closing a partial tunneled body does not affect later connections", ctx do
    tls = tunnel(ctx, ctx.token)

    :ok =
      :ssl.send(
        tls,
        "POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nshort"
      )

    :ok = :ssl.close(tls)

    tls = tunnel(ctx, ctx.token)
    {_, echoed} = request(tls, "GET /after-close HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert echoed["path"] == "/after-close"
  end

  test "an origin on a private or loopback address is refused before any connection" do
    ctx = start_rig(allow_private_upstreams: false)
    token = put_session(ctx, bearer_session("x"))

    {_tcp, reply} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(token))
    assert reply =~ "HTTP/1.1 403"

    for ip <- [
          {10, 1, 2, 3},
          {172, 16, 0, 1},
          {192, 168, 1, 1},
          {169, 254, 169, 254},
          {100, 64, 0, 1},
          {127, 0, 0, 1},
          {0, 0, 0, 0}
        ],
        do: assert(Proxy.private?(ip))

    for ip <- [{140, 82, 112, 3}, {172, 32, 0, 1}, {100, 128, 0, 1}, {8, 8, 8, 8}],
        do: refute(Proxy.private?(ip))
  end

  test "the rig refuses to pretend a refused CONNECT opened a tunnel", ctx do
    # Without this the helper would hand back a socket the proxy has
    # already answered 403 on, and every later assertion would fail
    # somewhere else entirely.
    Memory.put(ctx.store, ctx.token, %{
      ctx.session
      | rules: [%Rule{name: "only", pattern: "elsewhere.test", scheme: :passthrough}],
        unmatched_host_policy: :deny
    })

    assert_raise RuntimeError, ~r/answered .*403/, fn ->
      tunnel(ctx, ctx.token)
    end
  end

  test "a passthrough host is forwarded untouched", ctx do
    # A session whose rules name another host: nothing matches localhost.
    Memory.put(ctx.store, ctx.token, %{ctx.session | rules: []})
    tls = tunnel(ctx, ctx.token)

    {_, echoed} =
      request(
        tls,
        "GET /x HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer __github_token__\r\n\r\n"
      )

    assert echoed["headers"]["authorization"] == "Bearer __github_token__"
  end

  test "a denied host is 403 inside the tunnel", ctx do
    # A rule for one path of the host lets the tunnel open; the request
    # below is to another path, so it is unmatched inside the tunnel.
    Memory.put(ctx.store, ctx.token, %{
      ctx.session
      | rules: [%Rule{name: "narrow", pattern: "localhost/allowed/*", scheme: :passthrough}],
        unmatched_host_policy: :deny
    })

    tls = tunnel(ctx, ctx.token)
    :ok = :ssl.send(tls, "GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n")
    {:ok, reply} = :ssl.recv(tls, 0, 5_000)
    assert reply =~ "HTTP/1.1 403"
  end

  test "plain HTTP in absolute form is forwarded with the credential attached", ctx do
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

    :ok =
      :gen_tcp.send(
        tcp,
        "GET http://localhost:#{ctx.http_port}/plain?q=1 HTTP/1.1\r\nHost: localhost\r\n" <>
          "Proxy-Authorization: #{proxy_auth(ctx.token)}\r\n" <>
          "Authorization: Bearer __github_token__\r\n\r\n"
      )

    reply = read_until_closed(tcp)
    assert reply =~ "HTTP/1.1 200"
    [_, body] = String.split(reply, "\r\n\r\n", parts: 2)
    echoed = Jason.decode!(body)
    assert echoed["path"] == "/plain"
    assert echoed["headers"]["authorization"] == "Bearer ghp_real"
    refute Map.has_key?(echoed["headers"], "proxy-authorization")
  end

  test "plain HTTP with a body is forwarded whole", ctx do
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

    :ok =
      :gen_tcp.send(
        tcp,
        "POST http://localhost:#{ctx.http_port}/body HTTP/1.1\r\nHost: localhost\r\n" <>
          "Proxy-Authorization: #{proxy_auth(ctx.token)}\r\nContent-Length: 5\r\n\r\nhel"
      )

    Process.sleep(50)
    :ok = :gen_tcp.send(tcp, "lo")

    reply = read_until_closed(tcp)
    [_, body] = String.split(reply, "\r\n\r\n", parts: 2)
    assert Jason.decode!(body)["body"] == "hello"
  end

  test "plain HTTP under deny to an unmatched host is 403", ctx do
    Memory.put(ctx.store, ctx.token, %{ctx.session | rules: [], unmatched_host_policy: :deny})
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

    :ok =
      :gen_tcp.send(
        tcp,
        "GET http://localhost:#{ctx.http_port}/ HTTP/1.1\r\nHost: localhost\r\n" <>
          "Proxy-Authorization: #{proxy_auth(ctx.token)}\r\n\r\n"
      )

    assert read_until_closed(tcp) =~ "HTTP/1.1 403"
  end

  test "the request log names the session's meta and the rule, never a header", ctx do
    session = attach_request_telemetry(ctx)
    ctx = %{ctx | session: session}

    tls = tunnel(ctx, ctx.token)
    request(tls, "GET /logged HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer x\r\n\r\n")

    assert_receive {:request, %{count: 1},
                    %{
                      method: "GET",
                      host: "localhost",
                      path: "/logged",
                      outcome: :injected,
                      rule: "origin",
                      meta: %{conversation_id: "conv-1", user_id: "user-1"}
                    } = meta}

    refute Map.has_key?(meta, :headers)

    # Passthrough and denied outcomes, on the same event.
    Memory.put(ctx.store, ctx.token, %{ctx.session | rules: []})
    tls = tunnel(ctx, ctx.token)
    request(tls, "GET /through HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert_receive {:request, _, %{path: "/through", outcome: :passthrough, rule: nil}}

    Memory.put(ctx.store, ctx.token, %{
      ctx.session
      | rules: [%Rule{name: "n", pattern: "localhost/ok", scheme: :passthrough}],
        unmatched_host_policy: :deny
    })

    tls = tunnel(ctx, ctx.token)
    :ok = :ssl.send(tls, "GET /no HTTP/1.1\r\nHost: localhost\r\n\r\n")
    {:ok, _} = :ssl.recv(tls, 0, 5_000)
    assert_receive {:request, _, %{path: "/no", outcome: :denied, rule: nil}}
  end

  test "the request log carries the path and never the query, on both request paths", ctx do
    # A query can hold a credential the proxy never brokered — a signed URL
    # is one in itself — so the event's `path` is the URL path alone, while
    # the origin still receives the target byte for byte.
    secret = "sig-#{System.unique_integer([:positive])}-do-not-log"

    attach_request_telemetry(ctx)

    # Inside a CONNECT tunnel, where the target is origin-form.
    tls = tunnel(ctx, ctx.token)

    {_, echoed} =
      request(tls, "GET /tunneled?token=#{secret} HTTP/1.1\r\nHost: localhost\r\n\r\n")

    assert echoed["path"] == "/tunneled"
    assert echoed["query"] == "token=#{secret}"

    assert_receive {:request, _, %{path: "/tunneled"} = tunneled_meta}
    refute_logged(tunneled_meta, secret)

    # Absolute-form plain HTTP, where the target is a whole URL.
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

    :ok =
      :gen_tcp.send(
        tcp,
        "GET http://localhost:#{ctx.http_port}/absolute?token=#{secret} HTTP/1.1\r\n" <>
          "Host: localhost\r\nProxy-Authorization: #{proxy_auth(ctx.token)}\r\n\r\n"
      )

    [_, body] = String.split(read_until_closed(tcp), "\r\n\r\n", parts: 2)
    echoed = Jason.decode!(body)

    assert echoed["path"] == "/absolute"
    assert echoed["query"] == "token=#{secret}"

    assert_receive {:request, _, %{path: "/absolute"} = absolute_meta}
    refute_logged(absolute_meta, secret)
  end

  # ---------------------------------------------------------------------------
  # A credential a client puts in the URL

  describe "substitution into the request target" do
    setup ctx do
      session = %{
        attach_request_telemetry(ctx)
        | rules: [
            %Rule{
              name: "bot",
              pattern: "localhost",
              scheme: :substitute,
              placeholder: "__bot_token__",
              credential: "123456:AAE-real"
            }
          ]
      }

      Memory.put(ctx.store, ctx.token, session)
      %{session: session}
    end

    test "a placeholder in the path reaches the origin as the credential, through a tunnel",
         ctx do
      tls = tunnel(ctx, ctx.token)

      {head, echoed} =
        request(tls, "GET /bot__bot_token__/sendMessage HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert head =~ "HTTP/1.1 200"
      assert echoed["path"] == "/bot123456:AAE-real/sendMessage"
    end

    test "a placeholder in the query reaches the origin as the credential, through a tunnel",
         ctx do
      tls = tunnel(ctx, ctx.token)

      {_, echoed} =
        request(tls, "GET /v1/models?key=__bot_token__ HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert echoed["path"] == "/v1/models"
      assert echoed["query"] == "key=123456:AAE-real"
    end

    test "a placeholder in the path and in the query, over absolute-form plain HTTP", ctx do
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

      :ok =
        :gen_tcp.send(
          tcp,
          "GET http://localhost:#{ctx.http_port}/bot__bot_token__/send?key=__bot_token__ " <>
            "HTTP/1.1\r\nHost: localhost\r\n" <>
            "Proxy-Authorization: #{proxy_auth(ctx.token)}\r\n\r\n"
        )

      [_, body] = String.split(read_until_closed(tcp), "\r\n\r\n", parts: 2)
      echoed = Jason.decode!(body)

      assert echoed["path"] == "/bot123456:AAE-real/send"
      assert echoed["query"] == "key=123456:AAE-real"
    end

    test "the event carries the placeholder for a path, nothing for a query, never the credential",
         ctx do
      tls = tunnel(ctx, ctx.token)

      # A path substitution: the event names the target the *client* sent,
      # so the placeholder is what gets logged, not the credential.
      request(tls, "GET /bot__bot_token__/sendMessage HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert_receive {:request, _, %{path: "/bot__bot_token__/sendMessage"} = meta}
      refute_logged(meta, "123456:AAE-real")

      # A query substitution: row 0 already drops the query, so there is
      # nothing to log and nothing to leak.
      request(tls, "GET /v1/models?key=__bot_token__ HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert_receive {:request, _, %{path: "/v1/models"} = meta}
      refute_logged(meta, "123456:AAE-real")
      refute_logged(meta, "__bot_token__")
    end

    test "a rule whose placeholder is not usable as one is refused, and says why", ctx do
      Memory.put(ctx.store, ctx.token, %{
        ctx.session
        | rules: [
            %Rule{
              name: "loose",
              pattern: "localhost",
              scheme: :substitute,
              placeholder: "id",
              credential: "real-secret"
            }
          ]
      })

      tls = tunnel(ctx, ctx.token)

      log =
        capture_log(fn ->
          :ok = :ssl.send(tls, "GET /videos/id/1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
          {:ok, reply} = :ssl.recv(tls, 0, 5_000)
          assert reply =~ "HTTP/1.1 403"
        end)

      # Without the check this request would have gone to
      # /videos/real-secret/1 and put the credential in a path nobody chose.
      assert log =~ ~s(rule "loose")
      refute log =~ "real-secret"
    end

    test "a credential that would split the request line is refused, not forwarded", ctx do
      Memory.put(ctx.store, ctx.token, %{
        ctx.session
        | rules: [
            %Rule{
              name: "bad",
              pattern: "localhost",
              scheme: :substitute,
              placeholder: "__bot_token__",
              credential: "tok\r\nGET /evil HTTP/1.1"
            }
          ]
      })

      tls = tunnel(ctx, ctx.token)

      log =
        capture_log(fn ->
          :ok = :ssl.send(tls, "GET /bot__bot_token__/x HTTP/1.1\r\nHost: localhost\r\n\r\n")
          {:ok, reply} = :ssl.recv(tls, 0, 5_000)
          assert reply =~ "HTTP/1.1 403"
        end)

      # The operator has to fix this, so the line names the rule — and only
      # the rule.
      assert log =~ ~s(rule "bad")
      refute log =~ "GET /evil"
    end
  end

  # ---------------------------------------------------------------------------
  # The request event is terminal: it knows how the request ended

  describe "the terminal request event" do
    setup ctx do
      %{session: attach_request_telemetry(ctx)}
    end

    test "a tunneled request carries its status, a duration and no error", ctx do
      tls = tunnel(ctx, ctx.token)
      request(tls, "GET /ok HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert_receive {:request, %{count: 1, duration: duration},
                      %{path: "/ok", status: 200, error: nil, outcome: :injected}}

      assert is_integer(duration) and duration > 0
    end

    test "an absolute-form request carries its status too", ctx do
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

      :ok =
        :gen_tcp.send(
          tcp,
          "GET http://localhost:#{ctx.http_port}/plain-ok HTTP/1.1\r\nHost: localhost\r\n" <>
            "Proxy-Authorization: #{proxy_auth(ctx.token)}\r\n\r\n"
        )

      read_until_closed(tcp)

      assert_receive {:request, %{count: 1, duration: _},
                      %{path: "/plain-ok", status: 200, error: nil}}
    end

    test "two keep-alive responses on one tunnel are attributed to the right requests", ctx do
      tls = tunnel(ctx, ctx.token)

      request(tls, "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n")
      assert_receive {:request, _, %{path: "/first", status: 200}}

      # The origin answers 404 for nothing, so ask for a status that
      # differs another way: a second request must get its own event.
      request(tls, "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n")
      assert_receive {:request, _, %{path: "/second", status: 200, error: nil}}

      refute_receive {:request, _, _}, 100
    end

    test "a local refusal emits at once, with the status the proxy sent", ctx do
      Memory.put(ctx.store, ctx.token, %{
        ctx.session
        | rules: [%Rule{name: "n", pattern: "localhost/ok", scheme: :passthrough}],
          unmatched_host_policy: :deny
      })

      tls = tunnel(ctx, ctx.token)
      :ok = :ssl.send(tls, "GET /no HTTP/1.1\r\nHost: localhost\r\n\r\n")
      {:ok, _} = :ssl.recv(tls, 0, 5_000)

      assert_receive {:request, %{count: 1, duration: _},
                      %{path: "/no", outcome: :denied, status: 403, error: nil}}
    end

    test "a streamed response still streams, and its event waits for the end", ctx do
      tls = tunnel(ctx, ctx.token)
      stream = "event_stream_#{System.unique_integer([:positive])}"

      :ok =
        :ssl.send(
          tls,
          "GET /stream HTTP/1.1\r\nHost: localhost\r\nX-Stream-Name: #{stream}\r\n\r\n"
        )

      # The first chunk reaches the sandbox before the response is over —
      # framing must not have buffered it — and the event has not fired,
      # because the request has not ended.
      assert recv_until(tls, "data: first") =~ "data: first"
      refute_receive {:request, _, _}, 100

      send(String.to_atom(stream), :continue)
      recv_until(tls, "data: second")

      assert_receive {:request, %{duration: _}, %{path: "/stream", status: 200, error: nil}}
    end

    test "a WebSocket upgrade emits at the 101 and then leaves the frames alone", ctx do
      tls = tunnel(ctx, ctx.token)

      :ok =
        :ssl.send(
          tls,
          "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" <>
            "Connection: Upgrade\r\nSec-WebSocket-Key: #{Base.encode64("0123456789abcdef")}\r\n" <>
            "Sec-WebSocket-Version: 13\r\nAuthorization: Bearer __github_token__\r\n\r\n"
        )

      recv_until(tls, "101")
      assert_receive {:request, %{duration: _}, %{path: "/ws", status: 101, error: nil}}

      # The frames after it are still a byte pipe, and produce no events.
      mask = <<1, 2, 3, 4>>
      :ok = :ssl.send(tls, <<0x81, 0x82>> <> mask <> :crypto.exor("hi", binary_part(mask, 0, 2)))
      {:ok, frame} = :ssl.recv(tls, 0, 5_000)
      <<0x81, len, text::binary-size(len)>> = frame
      assert text == "Bearer ghp_real|hi"

      refute_receive {:request, _, _}, 100
    end

    test "an origin that closes the connection still ends its request cleanly", ctx do
      # The upstream side of the tunnel goes away under the proxy's feet
      # while the sandbox is still there. The response completed, so the
      # event says so: a status and no error.
      tls = tunnel(ctx, ctx.token)
      :ok = :ssl.send(tls, "GET /close HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert recv_until(tls, "closing") =~ "HTTP/1.1 200"
      assert_receive {:request, %{duration: _}, %{path: "/close", status: 200, error: nil}}
    end

    test "a request whose answer never comes emits with a terminal error", ctx do
      # The sandbox sends a request and walks away before the origin has
      # answered. The event still has to be emitted, and has to say why it
      # has no status.
      tls = tunnel(ctx, ctx.token)
      stream = "abandoned_#{System.unique_integer([:positive])}"

      :ok =
        :ssl.send(
          tls,
          "GET /stream HTTP/1.1\r\nHost: localhost\r\nX-Stream-Name: #{stream}\r\n\r\n"
        )

      recv_until(tls, "data: first")
      :ok = :ssl.close(tls)
      send(String.to_atom(stream), :continue)

      assert_receive {:request, %{duration: _}, %{path: "/stream", status: 200, error: error}},
                     2_000

      assert error in [:client_closed, :upstream_closed]
    end
  end

  # The event's own fields, whatever their shape, must not contain `secret`
  # anywhere: asserting on `path` alone would miss it leaking into another
  # field later.
  defp refute_logged(meta, secret) do
    refute inspect(meta) =~ secret
  end

  # ---------------------------------------------------------------------------
  # The 407 is an invitation to retry, not a dead end

  test "a 407 holds the connection open, so a client that negotiates can retry on it", ctx do
    # git's default, `http.proxyAuthMethod=anyauth`: CONNECT bare *in order
    # to* learn the scheme from the challenge, then retry with the
    # credential on the same socket. Closing after the 407 broke every
    # brokered clone in production.
    host_port = "localhost:#{ctx.https_port}"
    {tcp, challenge} = connect(ctx, host_port, nil)

    assert challenge =~ "HTTP/1.1 407"
    assert challenge =~ ~r/proxy-authenticate: Basic/i
    assert challenge =~ ~r/proxy-connection: Keep-Alive/i

    assert :ok = retry(tcp, host_port, proxy_auth(ctx.token))
    assert {:ok, reply} = :gen_tcp.recv(tcp, 0, 5_000)
    assert reply =~ "HTTP/1.1 200"
  end

  test "the retry is bounded: a client that never authenticates is dropped", ctx do
    host_port = "localhost:#{ctx.https_port}"
    {tcp, first} = connect(ctx, host_port, nil)
    assert first =~ ~r/proxy-connection: Keep-Alive/i

    :ok = retry(tcp, host_port, nil)
    {:ok, second} = :gen_tcp.recv(tcp, 0, 5_000)
    assert second =~ "HTTP/1.1 407"
    assert second =~ ~r/proxy-connection: Keep-Alive/i

    # The last attempt is answered without the invitation, and closed.
    :ok = retry(tcp, host_port, nil)
    {:ok, third} = :gen_tcp.recv(tcp, 0, 5_000)
    assert third =~ "HTTP/1.1 407"
    refute third =~ ~r/proxy-connection/i

    assert {:error, :closed} = :gen_tcp.recv(tcp, 0, 5_000)
  end

  test "an unauthenticated request carrying a body is answered and closed", ctx do
    # Holding this one open would leave the body in the stream with nothing
    # to consume it, and the next parse would read it as a request head.
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false], 5_000)

    :ok =
      :gen_tcp.send(
        tcp,
        "POST http://localhost:#{ctx.http_port}/x HTTP/1.1\r\nHost: localhost\r\n" <>
          "Content-Length: 5\r\n\r\nhello"
      )

    {:ok, reply} = :gen_tcp.recv(tcp, 0, 5_000)
    assert reply =~ "HTTP/1.1 407"
    refute reply =~ ~r/proxy-connection/i
    assert {:error, :closed} = :gen_tcp.recv(tcp, 0, 5_000)
  end

  test "a credential-less request logs at debug; a bad token still logs at info", ctx do
    # The blackbox liveness probe is a credential-less request every thirty
    # seconds. At `:info` it wrote ~2,880 lines a day and buried the real
    # refusals among them.
    no_credentials =
      capture_log(fn ->
        {_tcp, _} = connect(ctx, "localhost:#{ctx.https_port}", nil)
      end)

    refute no_credentials =~ "refused connection"

    bad_token =
      capture_log(fn ->
        {_tcp, _} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth("mb_nope"))
      end)

    assert bad_token =~ "refused connection: :unknown_token"
  end

  # ---------------------------------------------------------------------------
  # The connect event: one per connection, whatever the proxy decided

  test "every connection emits a connect event, so a failure ratio has a denominator", ctx do
    handler = "connect-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:managoat, :broker, :connect],
      fn _e, measurements, meta, pid -> send(pid, {:connect, measurements, meta}) end,
      self()
    )

    on_exit(fn -> :telemetry.detach(handler) end)

    {_tcp, _} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(ctx.token))

    assert_receive {:connect, %{count: 1},
                    %{
                      host: "localhost",
                      port: port,
                      outcome: :ok,
                      meta: %{conversation_id: "conv-1", user_id: "user-1"}
                    }}

    assert port == ctx.https_port

    # An origin that will not connect.
    {_tcp, _} = connect(ctx, "localhost:1", proxy_auth(ctx.token))
    assert_receive {:connect, _, %{host: "localhost", port: 1, outcome: :upstream_failed}}

    # A host outside a `deny` session's rules.
    Memory.put(ctx.store, ctx.token, %{
      ctx.session
      | rules: [%Rule{name: "x", pattern: "api.example.com", scheme: :passthrough}],
        unmatched_host_policy: :deny
    })

    {_tcp, _} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(ctx.token))
    assert_receive {:connect, _, %{host: "localhost", outcome: :denied}}

    # No credential: no session, so no destination has been read yet.
    {_tcp, _} = connect(ctx, "localhost:#{ctx.https_port}", nil)
    assert_receive {:connect, _, %{host: nil, port: nil, outcome: :unauthenticated, meta: %{}}}
  end

  # A second request head down a socket the proxy answered with a 407.
  defp retry(tcp, host_port, auth) do
    line = if auth, do: "Proxy-Authorization: #{auth}\r\n", else: ""
    :gen_tcp.send(tcp, "CONNECT #{host_port} HTTP/1.1\r\nHost: #{host_port}\r\n#{line}\r\n")
  end
end
