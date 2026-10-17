defmodule Managoat.Broker.PlainDNSPoolTest do
  # The resolver's file table is VM-global, so keep these tests serial and
  # restore its lookup policy and our dedicated fixture addresses afterward.
  use Managoat.Broker.ProxyCase, async: false
  alias Managoat.Broker.Proxy

  @first {127, 22, 0, 1}
  @second {127, 22, 0, 2}
  @public {192, 0, 2, 10}
  @host "pool-rotation.test"

  defmodule Origin do
    import Plug.Conn
    def init(opts), do: opts

    def call(conn, _) do
      peer = get_peer_data(conn)
      send_resp(conn, 200, "#{inspect(self())}:#{peer.port}")
    end
  end

  setup do
    lookup = :inet_db.res_option(:lookup)
    :inet_db.set_lookup([:file])

    on_exit(fn ->
      for ip <- [@first, @second, @public], do: :inet_db.del_host(ip)
      :inet_db.set_lookup(lookup)
    end)

    ctx = start_rig()

    first =
      start_supervised!({Bandit, plug: Origin, scheme: :http, ip: @first, port: 0}, id: :first)

    {:ok, {_, port}} = ThousandIsland.listener_info(first)
    start_supervised!({Bandit, plug: Origin, scheme: :http, ip: @second, port: port}, id: :second)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    on_exit(fn -> :gen_tcp.close(tcp) end)

    token =
      put_session(ctx, %Session{
        rules: [],
        unmatched_host_policy: :passthrough,
        meta: %{},
        expires_at: DateTime.add(DateTime.utc_now(), 600)
      })

    Map.merge(ctx, %{tcp: tcp, origin_port: port, token: token})
  end

  defp answers(addresses) do
    for ip <- [@first, @second, @public], do: :inet_db.del_host(ip)
    for ip <- addresses, do: :inet_db.add_host(ip, [String.to_charlist(@host)])
    assert Proxy.addresses(@host) == addresses
  end

  defp download(ctx, extra \\ "") do
    :ok =
      :gen_tcp.send(
        ctx.tcp,
        "GET http://#{@host}:#{ctx.origin_port}/object HTTP/1.1\r\nHost: #{@host}\r\n#{extra}Proxy-Authorization: #{proxy_auth(ctx.token)}\r\n\r\n"
      )

    {head, body} = read_plain_response(ctx.tcp)
    assert head =~ "200"
    body
  end

  test "reordered answers retain one connection and removing the selected IP retires it", ctx do
    answers([@first, @second])
    first = download(ctx)

    for _ <- 1..5 do
      answers([@second, @first])
      assert download(ctx) == first
      answers([@first, @second])
      assert download(ctx) == first
    end

    answers([@second])
    second = download(ctx)
    refute second == first
    answers([@first, @second])
    assert download(ctx) == second
  end

  test "changing headers retires the selected connection despite DNS overlap", ctx do
    answers([@first, @second])
    first = download(ctx)
    answers([@second, @first])
    second = download(ctx, "X-Fixture: changed\r\n")
    refute first == second
    answers([@first, @second])
    assert download(ctx, "X-Fixture: changed\r\n") == second
  end

  test "a mixed public/private answer set is refused in either order", ctx do
    strict = start_rig(allow_private_upstreams: false)

    token =
      put_session(strict, %Session{
        rules: [],
        unmatched_host_policy: :passthrough,
        expires_at: DateTime.add(DateTime.utc_now(), 600)
      })

    for ips <- [[@public, @first], [@first, @public]] do
      answers(ips)
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", strict.proxy_port, [:binary, active: false])

      :gen_tcp.send(
        tcp,
        "GET http://#{@host}:#{ctx.origin_port}/object HTTP/1.1\r\nHost: #{@host}\r\nProxy-Authorization: #{proxy_auth(token)}\r\n\r\n"
      )

      assert read_until_closed(tcp) =~ "403 Forbidden"
      :gen_tcp.close(tcp)
    end
  end
end
