defmodule Mix.Tasks.ExOauth2Provider.Gen.Config do
  @shortdoc "Generates ex_oauth2_provider config"

  @moduledoc """
  Generates ex_oauth2_provider migration files.

      mix ex_oauth2_provider.gen.config

  This generator will update the config at `config/config.exs`

  ## Arguments

    * `-r`, `--repo` - the repo module
    * `--config-file` - the configuration file to update
    * `--resource-owner` - defines the resource owner, default is MyApp.Users.User
  """
  use Mix.Task

  alias Mix.{Ecto, ExOauth2Provider, ExOauth2Provider.Config}

  @switches     [resource_owner: :string, config_file: :string]
  @default_opts [resource_owner: "MyApp.Users.User", config_file: "config/config.exs"]
  @mix_task     "ex_oauth2_provider.gen.migrations"

  @impl true
  def run(args) do
    ExOauth2Provider.no_umbrella!(@mix_task)

    args
    |> ExOauth2Provider.parse_options(@switches, @default_opts)
    |> parse(args)
    |> update_config_file()
  end

  defp parse({config, _parsed, _invalid}, args) do
    repos = Ecto.parse_repo(args)

    Map.put(config, :repos, repos)
  end

  defp update_config_file(config), do: Config.update(config)
end
