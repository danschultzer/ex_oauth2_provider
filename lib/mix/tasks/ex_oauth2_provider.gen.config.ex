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

  alias ExOauth2Provider.Config, as: ProviderConfig
  alias Mix.{Ecto, ExOauth2Provider, ExOauth2Provider.Config}

  @switches     [config_file: :string, context_app: :string, resource_owner: :string]
  @default_opts [config_file: "config/config.exs"]
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

  defp update_config_file(config) do
    context_app    = Map.get(config, :context_app) || ProviderConfig.otp_app()
    resource_owner = Map.get(config, :resource_owner) || Module.concat([ProviderConfig.app_base(context_app), "Users", "User"])
    config_file    = Map.get(config, :config_file)

    Config.update(context_app, config_file, Map.put(config, :resource_owner, resource_owner))
  end
end
