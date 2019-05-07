defmodule Mix.Tasks.ExOauth2Provider.Install do
  @shortdoc "Installs ExOauth2Provider"

  @moduledoc """
  Generates migrations, schema module files, and updates config.

        mix ex_oauth2_provider.install

        mix ex_oauth2_provider.install --no-config

  ## Arguments

    * `--no-config` -- Don't append to your `config/config.exs` file
    * `--no-migration` -- Don't create migration file
    * `--no-schemas` -- Don't create schema module files
  """

  use Mix.Task

  alias Mix.ExOauth2Provider
  alias Mix.Tasks.ExOauth2Provider.Gen.{Config, Migration, Schemas}

  @switches     [config: :boolean, migration: :boolean, schemas: :boolean]
  @default_opts [config: true, migration: true, schemas: true]
  @mix_task     "ex_oauth2_provider.install"

  @impl true
  def run(args) do
    ExOauth2Provider.no_umbrella!(@mix_task)

    args
    |> ExOauth2Provider.parse_options(@switches, @default_opts)
    |> parse()
    |> run_migration(args)
    |> run_schemas(args)
    |> run_config(args)
  end

  defp parse({config, _parsed, _invalid}), do: config

  defp run_migration(%{migration: true} = config, args) do
    Migration.run(args)

    config
  end
  defp run_migration(config, _args), do: config

  defp run_schemas(%{schemas: true} = config, args) do
    Schemas.run(args)

    config
  end
  defp run_schemas(config, _args), do: config

  defp run_config(%{config: true} = config, args) do
    Config.run(args)

    config
  end
  defp run_config(config, _args), do: config
end
