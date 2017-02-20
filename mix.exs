defmodule ExOauth2Provider.Mixfile do
  use Mix.Project

  @version "0.1.0"

  def project do
    [app: :ex_oauth2_provider,
     version: @version,
     elixir: "~> 1.4",
     elixirc_paths: _elixirc_paths(Mix.env),
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     preferred_cli_env: [ex_oauth2_provider: :test],
     deps: deps(),

     # Hex
     description: "No brainer OAuth 2.0 provider",
     package: package(),

     # Docs
     name: "ExOAuth2Provider",
     docs: [source_ref: "v#{@version}", main: "ExOauth2Provider",
            canonical: "http://hexdocs.pm/ex_oauth2_provider",
            source_url: "https://github.com/danschultzer/ex_oauth2_provider",
            extras: ["README.md"]]
    ]
  end

  def application do
    [applications: _applications(Mix.env)]
  end

  defp _applications(:test), do: [:postgrex, :ecto, :logger]
  defp _applications(_), do: [:logger]

  defp _elixirc_paths(:test), do: ["lib", "test/support"]
  defp _elixirc_paths(_), do: ["lib"]

  defp deps do
    [{:ecto, "~> 2.1"},
     {:plug, "~> 1.0 or ~> 1.1 or ~> 1.2 or ~> 1.3"},
     {:poison, "~> 2.0 or ~> 3.0"},
     {:postgrex, ">= 0.11.1", optional: true},

     # Dev and test dependencies
     {:ex_doc, "~> 0.14", only: :dev, runtime: false},
     {:ex_machina, "~> 1.0", only: :test}
   ]
  end

  defp package do
    [
      maintainers: ["Dan Shultzer"],
      licenses: ["MIT"],
      links: %{github: "https://github.com/danschultzer/ex_oauth2_provider"},
      files: ~w(lib web) ++ ~w(CHANGELOG.md LICENSE mix.exs README.md)
    ]
  end
end
