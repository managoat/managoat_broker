defmodule Managoat.Broker.PlainPoolTest do
  use Managoat.Broker.ProxyCase, async: true

  defmodule Origin do
    import Plug.Conn
    def init(opts), do: opts

    def call(conn, _) do
      conn =
        if conn.request_path == "/close",
          do: put_resp_header(conn, "connection", "close"),
          else: conn

      send_resp(conn, 200, Integer.to_string(get_peer_data(conn).port))
    end
  end

  setup do
    ctx = start_rig()

    origin =
      start_supervised!({Bandit, plug: Origin, scheme: :http, ip: {127, 0, 0, 1}, port: 0},
        id: make_ref()
      )

    {:ok, {_, port}} = ThousandIsland.listener_info(origin)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    on_exit(fn -> :gen_tcp.close(tcp) end)
    Map.merge(ctx, %{tcp: tcp, origin_port: port})
  end

  defp session do
    %Session{
      rules: [],
      unmatched_host_policy: :passthrough,
      meta: %{},
      expires_at: DateTime.add(DateTime.utc_now(), 600)
    }
  end

  defp request(ctx, token, path, method \\ "GET") do
    :ok =
      :gen_tcp.send(
        ctx.tcp,
        "#{method} http://localhost:#{ctx.origin_port}#{path} HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: #{proxy_auth(token)}\r\n\r\n"
      )

    {_head, body} = read_plain_response(ctx.tcp)
    body
  end

  test "many objects on one client use one origin connection", ctx do
    token = put_session(ctx, session())
    ports = for n <- 1..25, do: request(ctx, token, "/#{n}")
    assert length(Enum.uniq(ports)) == 1
  end

  test "changing tokens or effective credentials cannot inherit a connection", ctx do
    token = put_session(ctx, session())
    first = request(ctx, token, "/first")
    other = put_session(ctx, session())
    second = request(ctx, other, "/second")
    refute first == second

    Memory.put(ctx.store, other, %{
      session()
      | rules: [%Rule{pattern: "localhost", scheme: :bearer, credential: "rotated"}]
    })

    third = request(ctx, other, "/third")
    refute second == third
  end

  test "a declared upstream close is redialed and POST never takes a pooled connection", ctx do
    token = put_session(ctx, session())
    first = request(ctx, token, "/close")
    second = request(ctx, token, "/again")
    refute first == second
    third = request(ctx, token, "/post", "POST")
    refute second == third
    fourth = request(ctx, token, "/get")
    refute third == fourth
  end

  test "a refused first vetted address falls through to IPv6 before sending", ctx do
    origin =
      start_supervised!(
        {Bandit, plug: Origin, scheme: :http, ip: {0, 0, 0, 0, 0, 0, 0, 1}, port: 0},
        id: make_ref()
      )

    {:ok, {_, port}} = ThousandIsland.listener_info(origin)
    token = put_session(ctx, session())
    assert request(%{ctx | origin_port: port}, token, "/ipv6") =~ ~r/^\d+$/
  end

  for {label, response, expected} <- [
        {"trailers",
         "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\nx-check: yes\r\n\r\n",
         "x-check: yes"},
        {"partial body", "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\npart", "part"},
        {"malformed head", "not HTTP\r\n\r\n", "502"}
      ] do
    test "pooled GET handles #{label} without retry", ctx do
      parent = self()
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, port} = :inet.port(listener)

      spawn_link(fn ->
        {:ok, origin} = :gen_tcp.accept(listener)
        {:ok, _} = :gen_tcp.recv(origin, 0, 2_000)
        send(parent, :origin_once)
        :gen_tcp.send(origin, unquote(response))
        :gen_tcp.close(origin)
        :gen_tcp.close(listener)
      end)

      token = put_session(ctx, session())

      :ok =
        :gen_tcp.send(
          ctx.tcp,
          "GET http://localhost:#{port}/raw HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nProxy-Authorization: #{proxy_auth(token)}\r\n\r\n"
        )

      wire = read_until_closed(ctx.tcp)
      assert wire =~ unquote(expected)
      assert_receive :origin_once
      refute_receive :origin_once
    end
  end

  test "an unreachable POST origin returns 502 without a retry", ctx do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listener)
    :gen_tcp.close(listener)
    token = put_session(ctx, session())

    :gen_tcp.send(
      ctx.tcp,
      "POST http://localhost:#{port}/post HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: #{proxy_auth(token)}\r\n\r\n"
    )

    assert read_until_closed(ctx.tcp) =~ "502"
  end

  for method <- ["GET", "POST"] do
    test "#{method} binds Host to absolute authority after sandbox and template headers", ctx do
      rules = [
        %Rule{
          pattern: "localhost",
          scheme: :custom,
          template: %{"Host" => "wrong-template.example", "X-Token" => "{{ TOKEN }}"},
          credential: %{"TOKEN" => "fixture-secret"}
        }
      ]

      token = put_session(ctx, %{session() | rules: rules})

      :gen_tcp.send(
        ctx.tcp,
        "#{unquote(method)} http://localhost:#{ctx.http_port}/host HTTP/1.1\r\nHost: wrong-sandbox.example\r\nProxy-Authorization: #{proxy_auth(token)}\r\n\r\n"
      )

      {_, body} = read_plain_json(ctx.tcp)
      assert body["headers"]["host"] == "localhost:#{ctx.http_port}"
      assert body["headers"]["x-token"] == "fixture-secret"
    end
  end
end
