defmodule Managoat.Broker.MixProject do
  use Mix.Project

  @version "0.11.0"
  @source_url "https://github.com/managoat/managoat_broker"

  def project do
    [
      app: :managoat_broker,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
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
        summary: [threshold: 97]
      ]
    ]
  end

  # `mix precommit` runs in :test so that its compile, credo and test steps see
  # exactly what CI sees — .github/workflows/ci.yml sets MIX_ENV=test for the
  # whole job. The two steps that must not run there shell out to :dev.
  def cli do
    [preferred_envs: [precommit: :test]]
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

  # The CI gate, in CI's order, in one command. Keep this and
  # .github/workflows/ci.yml in step: a check that lives only in CI is a check
  # every contributor discovers by pushing.
  defp aliases do
    [
      precommit: [
        &deps_unlock_unused_changes_nothing/1,
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        &dialyzer_in_dev/1,
        "test --cover",
        &hex_build_in_dev/1
      ]
    ]
  end

  # Parity with CI's `mix deps.unlock --unused && git diff --exit-code
  # mix.lock`. A bare "deps.unlock --unused" step rewrites the lockfile and
  # exits 0, so the alias would pass while CI failed the same commit on the
  # diff. Compared against the file as it was a moment ago rather than against
  # git HEAD, so an uncommitted but legitimate lockfile edit (a dependency
  # added on this branch) does not trip it.
  defp deps_unlock_unused_changes_nothing(_args) do
    before = File.read!("mix.lock")
    Mix.Task.run("deps.unlock", ["--unused"])

    if File.read!("mix.lock") != before do
      Mix.raise(
        "mix.lock listed unused dependencies (deps.unlock --unused just pruned them). " <>
          "Commit the updated mix.lock — CI fails this via `git diff --exit-code mix.lock`."
      )
    end

    :ok
  end

  # MIX_ENV=dev on purpose, the same override CI makes: dialyzer analyzes the
  # shipped code, and the test env would drag test-only dependencies into the
  # analysis and into the cached PLT. A function rather than a "cmd ..." step
  # because `mix cmd` execs without a shell and cannot set the environment.
  defp dialyzer_in_dev(_args), do: mix_in_dev(["dialyzer"])

  # What `mix hex.publish` will build, in the environment it builds it in: a
  # dependency hex refuses (a git dep, a path dep) fails here rather than on
  # the PR. The tarball goes to a temporary directory because it is a check,
  # not an artifact, and nothing here should have to gitignore it.
  defp hex_build_in_dev(_args) do
    app = Atom.to_string(Mix.Project.config()[:app])
    mix_in_dev(["hex.build", "--output", Path.join(System.tmp_dir!(), app <> "-precommit.tar")])
  end

  defp mix_in_dev(args) do
    case Mix.shell().cmd(Enum.join(["mix" | args], " "), env: [{"MIX_ENV", "dev"}]) do
      0 -> :ok
      status -> Mix.raise("mix #{Enum.join(args, " ")} failed with exit status #{status}")
    end
  end
end
