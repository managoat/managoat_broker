defmodule Managoat.Broker.PlainKeepAliveTest do
  # Absolute-form plain HTTP, more than one request to a connection. The
  # acceptance list from #13, one test each.
  #
  # The sandbox's connection and the origin's are separate decisions and
  # only the first is kept: each request dials its own origin connection and
  # asks it to close. So there is no pooled socket to be caught being closed
  # underneath a request whose body has already been streamed away and
  # cannot be sent again.
  use Managoat.Broker.ProxyCase, async: true

  defmodule Marker do
    @moduledoc false
    # A second origin that says which origin it is, and what credential
    # arrived — so a request to it cannot be confused with a request to the
    # rig's own origin answering on a connection that was wrongly reused.
    import Plug.Conn

    def init(opts), do: opts

    def call(conn, _opts) do
      auth = conn |> get_req_header("authorization") |> List.first() || "none"
      send_resp(conn, 200, "second-origin|#{auth}")
    end
  end

  setup do
    start_rig()
  end

  defp start_marker_origin do
    pid =
      start_supervised!(
        {Bandit, plug: Marker, scheme: :http, port: 0, ip: {127, 0, 0, 1}},
        id: make_ref()
      )

    {:ok, {_, port}} = ThousandIsland.listener_info(pid)
    port
  end

  defp session(rules, policy \\ :passthrough) do
    %Session{
      rules: rules,
      unmatched_host_policy: policy,
      expires_at: DateTime.add(DateTime.utc_now(), 600, :second),
      meta: %{}
    }
  end

  defp open(ctx) do
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    tcp
  end

  defp get(tcp, token, url, extra \\ "") do
    :ok =
      :gen_tcp.send(
        tcp,
        "GET #{url} HTTP/1.1\r\nHost: localhost\r\n" <>
          "Proxy-Authorization: #{proxy_auth(token)}\r\n#{extra}\r\n"
      )
  end

  test "two requests to one origin ride one connection, both injected, one event each", ctx do
    session =
      session([%Rule{name: "origin", pattern: "localhost", scheme: :bearer, credential: "real"}])

    token = put_session(ctx, session)

    attach_request_telemetry(Map.merge(ctx, %{token: token, session: session}))

    tcp = open(ctx)

    get(tcp, token, "http://localhost:#{ctx.http_port}/first")
    {head, echoed} = read_plain_json(tcp)

    assert head =~ "HTTP/1.1 200"
    assert head =~ "connection: keep-alive"
    assert echoed["path"] == "/first"
    assert echoed["headers"]["authorization"] == "Bearer real"

    # The same socket, no reconnect. Before this the origin's `Connection:
    # close` reached the sandbox verbatim and a keep-alive client dutifully
    # hung up.
    get(tcp, token, "http://localhost:#{ctx.http_port}/second")
    {_head, echoed} = read_plain_json(tcp)

    assert echoed["path"] == "/second"
    assert echoed["headers"]["authorization"] == "Bearer real"

    assert_receive {:request, %{count: 1, duration: _},
                    %{path: "/first", status: 200, error: nil}}

    assert_receive {:request, %{count: 1, duration: _},
                    %{path: "/second", status: 200, error: nil}}

    refute_receive {:request, _, %{path: "/first"}}, 100
  end

  test "two requests to different origins on one connection are each routed and injected", ctx do
    second = start_marker_origin()

    token =
      put_session(
        ctx,
        session([
          %Rule{
            name: "first",
            pattern: "localhost:#{ctx.http_port}",
            scheme: :bearer,
            credential: "first-credential"
          },
          %Rule{
            name: "second",
            pattern: "localhost:#{second}",
            scheme: :bearer,
            credential: "second-credential"
          }
        ])
      )

    tcp = open(ctx)

    get(tcp, token, "http://localhost:#{ctx.http_port}/one")
    {_head, echoed} = read_plain_json(tcp)
    assert echoed["path"] == "/one"
    assert echoed["headers"]["authorization"] == "Bearer first-credential"

    # A different origin on the same sandbox connection: the marker's own
    # answer is what proves the second request was not served by the first
    # origin, and the credential proves the second rule matched it.
    get(tcp, token, "http://localhost:#{second}/two")
    {_head, body} = read_plain_response(tcp)
    assert body == "second-origin|Bearer second-credential"
  end

  test "a deny session refuses the second request too, not only the first", ctx do
    second = start_marker_origin()

    token =
      put_session(
        ctx,
        session(
          [
            %Rule{
              name: "allowed",
              pattern: "localhost:#{ctx.http_port}",
              scheme: :bearer,
              credential: "real"
            }
          ],
          :deny
        )
      )

    tcp = open(ctx)

    get(tcp, token, "http://localhost:#{ctx.http_port}/allowed")
    {_head, echoed} = read_plain_json(tcp)
    assert echoed["path"] == "/allowed"

    # The rules are matched per request, so the host nothing allows is
    # refused on the second request of a connection the first one kept open.
    get(tcp, token, "http://localhost:#{second}/denied")
    assert read_until_closed(tcp) =~ "HTTP/1.1 403"
  end

  test "a client that asks to close gets one request per connection", ctx do
    token =
      put_session(
        ctx,
        session([
          %Rule{name: "origin", pattern: "localhost", scheme: :bearer, credential: "real"}
        ])
      )

    tcp = open(ctx)
    get(tcp, token, "http://localhost:#{ctx.http_port}/once", "Connection: close\r\n")

    reply = read_until_closed(tcp)
    assert reply =~ "HTTP/1.1 200"
    assert reply =~ "connection: close"
  end

  test "an HTTP/1.0 client gets one request per connection", ctx do
    # Keep-alive was the exception in 1.0 and negotiating it is not worth
    # the ambiguity, so a 1.0 client is answered and closed.
    token =
      put_session(
        ctx,
        session([
          %Rule{name: "origin", pattern: "localhost", scheme: :bearer, credential: "real"}
        ])
      )

    tcp = open(ctx)

    :ok =
      :gen_tcp.send(
        tcp,
        "GET http://localhost:#{ctx.http_port}/old HTTP/1.0\r\nHost: localhost\r\n" <>
          "Proxy-Authorization: #{proxy_auth(token)}\r\n\r\n"
      )

    # The origin answers 1.0 because that is what it was asked in, and the
    # proxy re-emits the version it was given.
    reply = read_until_closed(tcp)
    assert reply =~ "200 OK"
    assert reply =~ "connection: close"
  end

  test "a response that ends only at the origin's close ends the connection too", ctx do
    # No content-length and no chunked framing: the body is everything up to
    # the close, so there is no boundary and nothing could follow it.
    port = start_unframed_origin("no framing here")

    token =
      put_session(
        ctx,
        session([
          %Rule{name: "origin", pattern: "localhost", scheme: :bearer, credential: "real"}
        ])
      )

    tcp = open(ctx)
    get(tcp, token, "http://localhost:#{port}/unframed")

    reply = read_until_closed(tcp)
    assert reply =~ "HTTP/1.1 200"
    assert reply =~ "connection: close"
    assert reply =~ "no framing here"
  end

  test "a large response streams through, and the connection is still good after", ctx do
    # Big enough that the body arrives over many reads rather than with the
    # head, which is the relay loop rather than its first step.
    session =
      session([%Rule{name: "origin", pattern: "localhost", scheme: :bearer, credential: "real"}])

    token = put_session(ctx, session)
    attach_request_telemetry(Map.merge(ctx, %{token: token, session: session}))

    body = String.duplicate("x", 256 * 1024)
    tcp = open(ctx)

    :ok =
      :gen_tcp.send(
        tcp,
        "POST http://localhost:#{ctx.http_port}/big HTTP/1.1\r\nHost: localhost\r\n" <>
          "Proxy-Authorization: #{proxy_auth(token)}\r\n" <>
          "Content-Length: #{byte_size(body)}\r\n\r\n" <> body
      )

    {_head, echoed} = read_plain_json(tcp)
    assert echoed["body"] == body

    assert_receive {:request, _, %{path: "/big", status: 200, error: nil}}

    get(tcp, token, "http://localhost:#{ctx.http_port}/after")
    {_head, echoed} = read_plain_json(tcp)
    assert echoed["path"] == "/after"
  end

  test "a HEAD response has no body to follow it and the connection survives", ctx do
    session =
      session([%Rule{name: "origin", pattern: "localhost", scheme: :bearer, credential: "real"}])

    token = put_session(ctx, session)
    tcp = open(ctx)

    for path <- ["/head-one", "/head-two"] do
      :ok =
        :gen_tcp.send(
          tcp,
          "HEAD http://localhost:#{ctx.http_port}#{path} HTTP/1.1\r\nHost: localhost\r\n" <>
            "Proxy-Authorization: #{proxy_auth(token)}\r\n\r\n"
        )

      {:ok, reply} = :gen_tcp.recv(tcp, 0, 5_000)
      assert reply =~ "HTTP/1.1 200"
      assert reply =~ "connection: keep-alive"
    end
  end

  test "an origin that closes before answering ends the connection, with the reason", ctx do
    port = start_silent_origin()

    session =
      session([%Rule{name: "origin", pattern: "localhost", scheme: :bearer, credential: "real"}])

    token = put_session(ctx, session)
    attach_request_telemetry(Map.merge(ctx, %{token: token, session: session}))

    tcp = open(ctx)
    get(tcp, token, "http://localhost:#{port}/nothing")

    # No head ever arrived, so there is nothing to re-emit and nothing to
    # say to the sandbox but the close.
    assert read_until_closed(tcp) == ""
    assert_receive {:request, _, %{path: "/nothing", status: nil, error: :upstream_closed}}
  end

  # An origin that takes a request and closes without answering.
  defp start_silent_origin do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false, reuseaddr: true])

    {:ok, port} = :inet.port(listen)

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listen, 5_000)
      {:ok, _request} = :gen_tcp.recv(socket, 0, 5_000)
      :gen_tcp.close(socket)
      :gen_tcp.close(listen)
    end)

    port
  end

  # An origin that answers with neither a length nor chunked framing and
  # then closes — which Bandit will not do, and which is the one response
  # shape that cannot be followed by another on the same connection.
  defp start_unframed_origin(body) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false, reuseaddr: true])

    {:ok, port} = :inet.port(listen)

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listen, 5_000)
      {:ok, _request} = :gen_tcp.recv(socket, 0, 5_000)
      :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n#{body}")
      :gen_tcp.close(socket)
      :gen_tcp.close(listen)
    end)

    port
  end
end
