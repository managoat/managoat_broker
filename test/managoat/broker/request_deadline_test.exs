defmodule Managoat.Broker.RequestDeadlineTest do
  # The wall-clock bound on reading one request, head and body. The other
  # timeouts are per `recv`, so a client that keeps sending — one byte at a
  # time, forever — never trips one; and the byte cap bounds volume rather
  # than time, so at that rate the default 1 GiB is reached in roughly eight
  # thousand years. This is the bound that closes it.
  use Managoat.Broker.ProxyCase, async: true

  # Short enough to make the tests quick, long enough that a loaded CI
  # runner is not what ends the request. Every drip below uses a gap far
  # shorter than the 300s per-read idle timeout, so no single read ever
  # stalls: the deadline is the only thing that can end these.
  @deadline 300

  setup do
    ctx = start_rig(request_read_timeout: @deadline)
    session = bearer_session("ghp_real")
    ctx = Map.merge(ctx, %{token: put_session(ctx, session), session: session})
    %{ctx | session: attach_request_telemetry(ctx)}
  end

  # Bytes one at a time, pausing between them. Stops early if the peer has
  # gone, which is the outcome under test rather than a failure.
  defp drip(socket, count, gap, send_fun) do
    Enum.reduce_while(1..count, :ok, fn _i, _acc ->
      case send_fun.(socket, "x") do
        :ok ->
          Process.sleep(gap)
          {:cont, :ok}

        {:error, _} = error ->
          {:halt, error}
      end
    end)
  end

  describe "inside a tunnel" do
    test "a body dripped past the deadline ends the request, though no read ever stalls", ctx do
      tls = tunnel(ctx, ctx.token)

      :ok =
        :ssl.send(tls, "POST /slow HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\n\r\n")

      drip(tls, 8, div(@deadline, 2), &:ssl.send/2)

      # Nothing is written back: the origin already holds a partial body, so
      # there is nothing honest left to say — the same choice the request
      # cap makes when a chunked body passes it while streaming.
      assert {:error, :closed} = :ssl.recv(tls, 0, 5_000)

      assert_receive {:request, %{count: 1, duration: _},
                      %{path: "/slow", error: :request_timeout, outcome: :injected}}
    end

    test "a head dripped past the deadline is answered 408", ctx do
      # Here the proxy has told the origin nothing, so there is a client to
      # answer and it gets a status rather than a dropped socket.
      tls = tunnel(ctx, ctx.token)
      :ok = :ssl.send(tls, "GET /never-finished HTTP/1.1\r\n")

      assert {:ok, reply} = :ssl.recv(tls, 0, 5_000)
      assert reply =~ "HTTP/1.1 408"

      # A head that never arrived has no method and no path, so the event
      # carries what is known and leaves the rest nil. It is still one
      # terminal event, which is what the host's audit log counts.
      assert_receive {:request, %{count: 1, duration: _},
                      %{
                        method: nil,
                        path: nil,
                        host: "localhost",
                        status: 408,
                        error: :request_timeout
                      }}
    end

    test "a long response is not bounded by it", ctx do
      # The reason this is a request-read deadline and not a connection one:
      # a `git clone` or an SSE stream runs long on the way *back*, and that
      # is the traffic this proxy exists for. `/stream` holds its second
      # chunk until told, here for several times the deadline.
      stream = "deadline-stream-#{System.unique_integer([:positive])}"
      tls = tunnel(ctx, ctx.token)

      :ok =
        :ssl.send(
          tls,
          "GET /stream HTTP/1.1\r\nHost: localhost\r\nx-stream-name: #{stream}\r\n\r\n"
        )

      recv_until(tls, "data: first")
      Process.sleep(@deadline * 3)
      send(String.to_atom(stream), :continue)

      assert recv_until(tls, "data: second") =~ "data: second"
      assert_receive {:request, _, %{path: "/stream", status: 200}}, 5_000
    end

    test "an ordinary request is untouched by it", ctx do
      tls = tunnel(ctx, ctx.token)
      {_, echoed} = request(tls, "GET /prompt HTTP/1.1\r\nHost: localhost\r\n\r\n")
      assert echoed["path"] == "/prompt"

      # And the deadline is per request, not per connection: a tunnel that
      # has been open for longer than one still serves the next request.
      Process.sleep(@deadline * 2)
      {_, echoed} = request(tls, "GET /later HTTP/1.1\r\nHost: localhost\r\n\r\n")
      assert echoed["path"] == "/later"
    end
  end

  describe "with the bound turned off" do
    setup do
      ctx = start_rig(request_read_timeout: :infinity)
      session = bearer_session("ghp_real")
      Map.merge(ctx, %{token: put_session(ctx, session), session: session})
    end

    test "a drip that would have been cut off is forwarded whole", ctx do
      # The escape hatch a host with legitimately slow uploads needs, and
      # the behaviour every release before this one had.
      tls = tunnel(ctx, ctx.token)

      :ok = :ssl.send(tls, "POST /slow HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n")
      assert :ok = drip(tls, 4, @deadline, &:ssl.send/2)

      {_, echoed} = read_response(tls, "")
      assert echoed["body"] == "xxxx"
    end
  end

  describe "on the absolute-form path" do
    test "a body dripped past the deadline ends the request", ctx do
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

      :ok =
        :gen_tcp.send(
          tcp,
          "POST http://localhost:#{ctx.http_port}/slow HTTP/1.1\r\nHost: localhost\r\n" <>
            "Proxy-Authorization: #{proxy_auth(ctx.token)}\r\nContent-Length: 8\r\n\r\n"
        )

      drip(tcp, 8, div(@deadline, 2), &:gen_tcp.send/2)

      assert read_until_closed(tcp) == ""

      assert_receive {:request, %{count: 1, duration: _},
                      %{path: "/slow", error: :request_timeout}}
    end

    test "a head dripped past the deadline is answered 408", ctx do
      # Before authentication there is no session, so this one is answered
      # and closed without a request event — there is nothing to attribute
      # one to, as on any unauthenticated connection.
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
      :ok = :gen_tcp.send(tcp, "GET http://localhost/slow HTTP/1.1\r\n")

      assert read_until_closed(tcp) =~ "HTTP/1.1 408"
      refute_receive {:request, _, _}, 200
    end
  end
end
