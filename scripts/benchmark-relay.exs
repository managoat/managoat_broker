# Run with MIX_ENV=test mise exec -- mix run scripts/benchmark-relay.exs.
# Loopback only; no external origin or production session. Compares observer
# overhead, not network placement. rep=0 warms up each path. Large response
# construction is included in time_total; compare the body interval separately.
ExUnit.start()
Logger.configure(level: :warning)

defmodule BulkOrigin do
  import Plug.Conn
  def init(_), do: nil
  def call(conn, _), do: send_resp(conn, 200, :binary.copy("x", 105_000_000))
end

defmodule RelayBenchmark do
  use Managoat.Broker.ProxyCase, async: false

  @tag timeout: 180_000
  test "local 105 MB TLS relay with diagnostics off and on" do
    {ca, tls} = origin_tls()

    origin =
      start_supervised!(
        {Bandit,
         plug: BulkOrigin,
         scheme: :https,
         port: 0,
         ip: {127, 0, 0, 1},
         thousand_island_options: [transport_options: tls]}
      )

    {:ok, {_, port}} = ThousandIsland.listener_info(origin)
    directory = Path.join(System.tmp_dir!(), "broker-relay-#{System.unique_integer([:positive])}")
    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    origin_pem = Path.join(directory, "origin.pem")
    File.write!(origin_pem, X509.Certificate.to_pem(ca))

    rigs =
      for {label, interval} <- [{"off", nil}, {"on", 5_000}] do
        ctx =
          start_rig(extra_cacerts: [X509.Certificate.to_der(ca)], diagnostics_interval: interval)

        token =
          put_session(ctx, %Session{
            rules: [],
            unmatched_host_policy: :passthrough,
            expires_at: DateTime.add(DateTime.utc_now(), 600)
          })

        pem = Path.join(directory, "#{label}.pem")
        File.write!(pem, Managoat.Broker.ca_pem(ctx.name))

        {label,
         [
           "--proxy",
           "http://127.0.0.1:#{ctx.proxy_port}",
           "--proxy-user",
           "#{token}:test",
           "--cacert",
           pem
         ]}
      end

    for rep <- 0..6 do
      configs = [{"direct", ["--proxy", "", "--cacert", origin_pem]} | rigs]
      configs = if rem(rep, 2) == 0, do: configs, else: Enum.reverse(configs)

      for {label, args} <- configs do
        {json, status} =
          System.cmd(
            "curl",
            [
              "--silent",
              "--show-error",
              "--noproxy",
              "",
              "--output",
              "/dev/null",
              "--max-time",
              "30",
              "--write-out",
              "%{json}"
            ] ++ args ++ ["https://localhost:#{port}/bulk"]
          )

        assert status == 0

        result =
          Jason.decode!(json)
          |> Map.take(
            ~w(time_namelookup time_connect time_appconnect time_starttransfer time_total size_download speed_download)
          )

        IO.puts(Jason.encode!(Map.merge(result, %{label: label, rep: rep})))
      end
    end
  end
end
