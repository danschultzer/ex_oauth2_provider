defmodule ExOauth2Provider.Mixfile do
  use Mix.Project

  @version "0.4.4"

  def project do
    [app: :ex_oauth2_provider,
     version: @version,
     elixir: "~> 1.8",
     elixirc_paths: elixirc_paths(Mix.env),
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     preferred_cli_env: [credo: :test, ex_doc: :test],
     deps: deps(),

     # Hex
     description: "No brainer OAuth 2.0 provider",
     package: package(),

     # Docs
     name: "ExOauth2Provider",
     docs: [source_ref: "v#{@version}",
            main: "ExOauth2Provider",
            canonical: "http://hexdocs.pm/ex_oauth2_provider",
            source_url: "https://github.com/danschultzer/ex_oauth2_provider",
            extras: ["README.md"]]
    ]
  end

  def application do
    [extra_applications: extra_applications(Mix.env)]
  end

  defp extra_applications(:test), do: [:postgrex, :ecto, :logger]
  defp extra_applications(_), do: [:logger]

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [{:ecto, "~> 3.0"},
     {:plug, ">= 1.0.0 and < 1.8.0"},

     # Dev and test dependencies
     {:credo, "~> 0.10", only: [:dev, :test]},
     {:ex_doc, ">= 0.0.0", only: :dev},
     {:ecto_sql, "~> 3.0.0", only: [:test]},
     {:plug_cowboy, "~> 2.0", only: [:test]},
     {:postgrex, "~> 0.14", only: :test}]
  end

  defp package do
    [
      maintainers: ["Dan Shultzer", "Benjamin Schultzer"],
      licenses: ["MIT"],
      links: %{github: "https://github.com/danschultzer/ex_oauth2_provider"},
      files: ~w(lib LICENSE mix.exs README.md)
    ]
  end
end
