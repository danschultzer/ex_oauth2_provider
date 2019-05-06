defmodule Mix.Tasks.ExOauth2Provider.Gen.Schemas do
  @shortdoc "Generates ex_oauth2_provider schema files"

  @moduledoc """
  Generates ex_oauth2_provider schema files.

      mix ex_oauth2_provider.gen.schemas -r MyApp.Repo

      mix ex_oauth2_provider.gen.schemas -r MyApp.Repo --namespace oauth2

      This generator will add the oauth2 migration file in `priv/repo/migrations`.

  ## Arguments

    * `-r`, `--repo` - the repo module
    * `--binary-id` - use binary id for primary key
    * `--namespace` - schema namespace to use, defaults to `oauth`
  """
  use Mix.Task

  alias ExOauth2Provider.Config
  alias Mix.{Ecto, ExOauth2Provider, ExOauth2Provider.Schema}

  @switches [binary_id: :boolean, context_app: :string]
  @default_opts [binary_id: false]
  @mix_task "ex_oauth2_provider.gen.migrations"

  @impl true
  def run(args) do
    ExOauth2Provider.no_umbrella!(@mix_task)

    args
    |> ExOauth2Provider.parse_options(@switches, @default_opts)
    |> parse()
    |> create_schema_files(args)
  end

  defp parse({config, parsed, _invalid}) do
    namespace = case parsed do
      [namespace] -> namespace
      _           -> "oauth"
    end

    Map.put(config, :schema_namespace, namespace)
  end

  defp create_schema_files(config, args) do
    args
    |> Ecto.parse_repo()
    |> Enum.map(&Ecto.ensure_repo(&1, args))
    |> Enum.map(&Map.put(config, :repo, &1))
    |> Enum.each(&create_schema_files/1)
  end

  defp create_schema_files(%{binary_id: binary_id, schema_namespace: schema_namespace} = config) do
    context_app = Map.get(config, :context_app) || Config.otp_app()

    Schema.create_schema_files(context_app, schema_namespace, binary_id: binary_id)
  end
end
