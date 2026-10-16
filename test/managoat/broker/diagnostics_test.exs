defmodule Managoat.Broker.DiagnosticsTest do
  use Managoat.Broker.ProxyCase, async: true

  alias Managoat.Broker.Diagnostics

  setup do
    ctx = start_rig(diagnostics_interval: 25)
    id = make_ref()
    session = bearer_session("test-secret", %{test_id: id, conversation_id: "diagnostic-test"})
    token = put_session(ctx, session)

    :telemetry.attach_many(
      id,
      [[:managoat, :broker, :diagnostic], [:managoat, :broker, :request]],
      &__MODULE__.capture/4,
      {self(), id}
    )

    on_exit(fn -> :telemetry.detach(id) end)
    Map.merge(ctx, %{token: token, session: session})
  end

  def capture(
        [:managoat, :broker, kind],
        measurements,
        %{meta: %{test_id: id}} = meta,
        {pid, id}
      ),
      do: send(pid, {kind, measurements, meta})

  def capture(_event, _measurements, _meta, _config), do: :ok

  test "a stalled origin before headers is visible before the client gives up", ctx do
    {port, origin} = stalled_origin(ctx)
    tls = tunnel(ctx, ctx.token, "localhost:#{port}")
    :ok = :ssl.send(tls, "GET /secret-path?token=secret HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert_receive {:origin_request, _}, 2_000
    assert_receive {:diagnostic, %{}, %{event: :request_start, connection_id: connection}}, 2_000

    assert_receive {:diagnostic, %{pending_requests: 1, upstream_bytes: 0} = counts,
                    %{event: :progress, connection_id: ^connection, client_writing: false} = meta},
                   2_000

    refute Map.has_key?(counts, :first_byte)
    refute inspect(meta) =~ "secret"
    :ssl.close(tls)

    assert_receive {:request, _,
                    %{connection_id: ^connection, status: nil, error: :client_closed}},
                   2_000

    assert_receive {:diagnostic, %{requests: 1, pending_requests: 0}, %{event: :stop}}, 2_000
    send(origin, :close)
  end

  test "a partial body is counted and a paused stream can continue", ctx do
    {port, origin} = stalled_origin(ctx)
    tls = tunnel(ctx, ctx.token, "localhost:#{port}")
    :ok = :ssl.send(tls, "GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert_receive {:origin_request, _}, 2_000
    first = "HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nabc"
    send(origin, {:write, first})
    assert recv_until(tls, "abc") == first
    bytes = byte_size(first)

    assert_receive {:diagnostic,
                    %{
                      upstream_bytes: ^bytes,
                      client_bytes: ^bytes,
                      pending_requests: 1,
                      first_byte: first_byte,
                      upstream_idle: idle
                    }, %{event: :progress}},
                   2_000

    assert first_byte >= 0 and idle >= 0
    # A progress report is an observation, never a response deadline.
    send(origin, {:write, "def"})
    assert {:ok, "def"} = :ssl.recv(tls, 3, 2_000)
    :ssl.close(tls)
    total = bytes + 3

    assert_receive {:diagnostic,
                    %{client_bytes: ^total, upstream_bytes: ^total, pending_requests: 0},
                    %{event: :stop}},
                   2_000

    send(origin, :close)
  end

  test "failed sandbox TLS setup carries the session and phase", ctx do
    {tcp, reply} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(ctx.token))
    assert reply =~ "200"
    :gen_tcp.close(tcp)

    assert_receive {:diagnostic, %{duration: duration},
                    %{
                      event: :phase,
                      phase: :client_tls,
                      outcome: :error,
                      meta: %{conversation_id: "diagnostic-test"}
                    }},
                   2_000

    assert duration >= 0
    assert_receive {:diagnostic, %{requests: 0}, %{event: :stop}}, 2_000
  end

  test "DNS and upstream failures are attributed before HTTP exists", ctx do
    for {host, phase} <- [{"missing.invalid:443", :dns}, {"localhost:1", :upstream_connect}] do
      {tcp, reply} = connect(ctx, host, proxy_auth(ctx.token))
      assert reply =~ "502"
      :gen_tcp.close(tcp)
      assert_receive {:diagnostic, _, %{event: :phase, phase: ^phase, outcome: :error}}, 2_000
      assert_receive {:diagnostic, %{requests: 0}, %{event: :stop}}, 2_000
    end
  end

  test "the sampler runs while a client write is blocked", ctx do
    trace = Diagnostics.start(25, %{host: "localhost", port: 443, meta: ctx.session.meta})
    request = Diagnostics.request(trace, %{})
    Diagnostics.received(trace, 123)
    owner = self()

    writer =
      Task.async(fn ->
        Diagnostics.write(trace, 123, fn ->
          send(owner, :writing)
          receive do: (:release -> :ok)
        end)
      end)

    assert_receive :writing

    assert_receive {:diagnostic,
                    %{upstream_bytes: 123, client_bytes: 0, client_write_in_flight: elapsed},
                    %{event: :progress, client_writing: true}},
                   2_000

    assert elapsed > 0
    send(writer.pid, :release)
    assert Task.await(writer) == :ok
    Diagnostics.finished(request)
    Diagnostics.stop(trace, :test_finished)

    assert_receive {:diagnostic, %{client_bytes: 123, client_write_duration: duration},
                    %{event: :stop, client_writing: false}},
                   2_000

    assert duration > 0
  end

  test "failed writes are timed but are not counted as delivered", ctx do
    trace = Diagnostics.start(25, %{host: "localhost", port: 443, meta: ctx.session.meta})
    assert Diagnostics.write(trace, 42, fn -> {:error, :closed} end) == {:error, :closed}
    Diagnostics.stop(trace, :test_finished)
    assert_receive {:diagnostic, %{client_bytes: 0}, %{event: :stop}}, 2_000
  end

  test "an observer exits with its handler even without orderly teardown", ctx do
    owner = self()

    task =
      spawn(fn ->
        trace = Diagnostics.start(25, %{host: "localhost", port: 443, meta: ctx.session.meta})
        send(owner, {:observer, trace.pid})
        receive do: (:finish -> :ok)
      end)

    assert_receive {:observer, observer}
    ref = Process.monitor(observer)
    send(task, :finish)
    assert_receive {:diagnostic, _, %{event: :stop, reason: :handler_exit}}, 2_000
    assert_receive {:DOWN, ^ref, :process, ^observer, :normal}, 2_000
  end

  test "invalid sample intervals fail at listener startup" do
    for interval <- [0, -1, :infinity] do
      assert_raise ArgumentError, ~r/diagnostics_interval/, fn ->
        Managoat.Broker.start_link(
          port: 0,
          store: Memory,
          ca_seed: seed(),
          diagnostics_interval: interval
        )
      end
    end
  end

  test "keep-alive request starts and terminal events share unique IDs", ctx do
    tls = tunnel(ctx, ctx.token)

    for path <- ["/first", "/second"] do
      request(tls, "GET #{path} HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert_receive {:diagnostic, _,
                      %{event: :request_start, request_id: id, connection_id: connection}},
                     2_000

      assert_receive {:request, _,
                      %{request_id: ^id, connection_id: ^connection, status: 200, error: nil}},
                     2_000

      suffix = if path == "/first", do: ":1", else: ":2"
      assert id == connection <> suffix
    end

    :ssl.close(tls)
    assert_receive {:diagnostic, %{requests: 2, pending_requests: 0}, %{event: :stop}}, 2_000
  end

  test "idle keep-alive tunnels do not produce progress noise", ctx do
    trace = Diagnostics.start(10, %{host: "localhost", port: 443, meta: ctx.session.meta})
    Diagnostics.measure(trace, :client_tls, fn -> {:ok, :connected} end)
    assert_receive {:diagnostic, _, %{event: :phase}}, 2_000
    refute_receive {:diagnostic, _, %{event: :progress}}, 50
    Diagnostics.stop(trace, :test_finished)
    assert_receive {:diagnostic, _, %{event: :stop}}, 2_000
  end

  defp stalled_origin(ctx) do
    {:ok, listener} = :ssl.listen(0, [:binary, active: false] ++ ctx.origin_tls)
    {:ok, {_, port}} = :ssl.sockname(listener)
    owner = self()

    task =
      start_supervised!(
        {Task,
         fn ->
           {:ok, socket} = :ssl.transport_accept(listener, 5_000)
           {:ok, socket} = :ssl.handshake(socket, 5_000)
           send(owner, {:origin_request, recv_until(socket, "\r\n\r\n")})
           origin_loop(socket)
         end}
      )

    on_exit(fn -> :ssl.close(listener) end)
    {port, task}
  end

  defp origin_loop(socket) do
    receive do
      {:write, bytes} ->
        :ok = :ssl.send(socket, bytes)
        origin_loop(socket)

      :close ->
        :ssl.close(socket)
    end
  end
end
