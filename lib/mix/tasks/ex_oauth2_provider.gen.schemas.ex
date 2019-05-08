defmodule Mix.Tasks.ExOauth2Provider.Gen.Schemas do
  @shortdoc "Generates ExOauth2Provider schema files"

  @moduledoc """
  Generates schema files.

      mix ex_oauth2_provider.gen.schemas

      mix ex_oauth2_provider.gen.schemas --binary-id --namespace oauth2

  ## Arguments

    * `--binary-id` - use binary id for primary keys
    * `--namespace` - namespace to prepend table and schema module name
    * `--context-app` - context app to use for path and module names
  """
  use Mix.Task

  alias ExOauth2Provider.Config
  alias Mix.{ExOauth2Provider, ExOauth2Provider.Schema}

  @switches     [binary_id: :boolean, context_app: :string, namespace: :string]
  @default_opts [binary_id: false, namespace: "oauth"]
  @mix_task     "ex_oauth2_provider.gen.migrations"

  @impl true
  def run(args) do
    ExOauth2Provider.no_umbrella!(@mix_task)

    args
    |> ExOauth2Provider.parse_options(@switches, @default_opts)
    |> parse()
    |> create_schema_files()
  end

  defp parse({config, _parsed, _invalid}), do: config

  defp create_schema_files(%{binary_id: binary_id, namespace: namespace} = config) do
   context_app = Map.get(config, :context_app) || Config.otp_app()

    Schema.create_schema_files(context_app, namespace, binary_id: binary_id)
  end
end
