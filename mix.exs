defmodule Managoat.Broker.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/managoat/managoat_broker"

  def project do
    [
      app: :managoat_broker,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "An egress credential proxy for sandboxed agents: CONNECT and absolute-form forward proxy that attaches the real credential where the sandbox sent a placeholder, behind a session-store behaviour.",
      package: package(),
      source_url: @source_url,
      docs: docs(),
      dialyzer: dialyzer(),
      test_coverage: [
        # What this suite measures on its own: the proxy end to end against a
        # real Bandit HTTPS origin, the CA, the injector, the HTTP slice and
        # the in-memory store. Raise it as the library's own tests grow;
        # never lower it.
        summary: [threshold: 85]
      ]
    ]
  end

  def application do
    [extra_applications: [:logger, :ssl, :public_key, :crypto]]
  end

  # The end-to-end rig (a Bandit origin, the sandbox-shaped client) is test
  # support, not part of the package.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Tooling for the repository, not the package: docs for hexdocs.pm (built
      # by `mix hex.publish`), credo and dialyzer for CI. dialyxir is pinned to
      # the commit that added OTP 28 support; 1.4.7 crashes on OTP 28 warnings.
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir,
       github: "jeremyjh/dialyxir",
       ref: "3553678f4d69281ac6db61034bcf35bcb30cfd78",
       only: [:dev, :test],
       runtime: false},
      # The listener. Bandit sits on the same library, so a Phoenix host
      # already has it; it is named here because the proxy handler is written
      # against it directly.
      {:thousand_island, "~> 1.5"},
      # Certificate building for the derived root and the per-host leaves.
      # Pure Elixir over :public_key.
      {:x509, "~> 0.9"},
      {:telemetry, "~> 1.0"},
      # Test only: a real HTTPS origin behind the proxy, a WebSocket echo on
      # it, and JSON for what the origin echoes back. jason is :dev as well
      # because credo depends on it in :dev; with only :test here, Mix
      # refuses the divergence once the library stands alone.
      {:bandit, "~> 1.5", only: :test},
      {:websock_adapter, "~> 0.5", only: :test},
      {:jason, "~> 1.2", only: [:dev, :test]}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url, "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"},
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE NOTICE)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end

  defp dialyzer do
    [
      ignore_warnings: ".dialyzer_ignore.exs",
      # A fixed path so CI can cache the PLT across runs.
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
    ]
  end
end
