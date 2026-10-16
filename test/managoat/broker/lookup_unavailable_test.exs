defmodule Managoat.Broker.LookupUnavailableTest do
  use Managoat.Broker.ProxyCase, async: true

  alias Managoat.Broker.Store

  defmodule UnavailableStore do
    @behaviour Store
    @impl Store
    def lookup(_instance, _token), do: {:error, :unavailable}
    @impl Store
    def lookup(_token), do: {:error, :unavailable}
  end

  test "both store callback forms preserve unavailability" do
    assert Store.lookup(UnavailableStore, "private-token") == {:error, :unavailable}
    assert Store.lookup({UnavailableStore, :instance}, "private-token") == {:error, :unavailable}
  end

  for method <- [:connect, :absolute] do
    test "#{method}: unavailable authority closes with 503 before dialing an upstream" do
      ctx = start_rig(store_module: UnavailableStore)
      {:ok, origin} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_tcp.close(origin) end)
      {:ok, {_, port}} = :inet.sockname(origin)
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
      target = "127.0.0.1:#{port}"

      line =
        case unquote(method) do
          :connect -> "CONNECT #{target} HTTP/1.1"
          :absolute -> "GET http://#{target}/private-path HTTP/1.1"
        end

      owner = self()
      handler = make_ref()
      :ok = :telemetry.attach(handler, [:managoat, :broker, :connect], &__MODULE__.event/4, owner)
      on_exit(fn -> :telemetry.detach(handler) end)

      :ok =
        :gen_tcp.send(
          tcp,
          line <>
            "\r\nHost: #{target}\r\n" <>
            "Proxy-Authorization: #{proxy_auth("private-token")}\r\n\r\n"
        )

      response = read_until_closed(tcp)
      assert response =~ "HTTP/1.1 503 Service Unavailable"
      refute String.downcase(response) =~ "proxy-authenticate:"
      refute response =~ "private-token"
      refute response =~ "private-path"

      assert_receive {:lookup_event, %{count: 1},
                      %{outcome: :lookup_unavailable, host: nil, port: nil, meta: %{}}}

      assert {:error, :timeout} = :gen_tcp.accept(origin, 50)
    end
  end

  def event(_event, measurements, %{outcome: :lookup_unavailable} = metadata, owner),
    do: send(owner, {:lookup_event, measurements, metadata})

  def event(_, _, _, _), do: :ok
end
