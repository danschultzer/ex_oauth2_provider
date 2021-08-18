defmodule Mix.Tasks.ExOauth2Provider.Gen.Schemas do
  @shortdoc "Generates ExOauth2Provider schema files"

  @moduledoc """
  Generates schema files.

      mix ex_oauth2_provider.gen.schemas

      mix ex_oauth2_provider.gen.schemas --binary-id --namespace oauth2

  ## Arguments

    * `--binary-id` - use binary id for primary keys
    * `--context-app` - context app to use for path and module names
    * `--device-code` - generate an optional schema for device code grants
    * `--namespace` - namespace to prepend table and schema module name
  """
  use Mix.Task

  alias Mix.{ExOauth2Provider, ExOauth2Provider.Schema}

  @switches [
    binary_id: :boolean,
    context_app: :string,
    device_code: :boolean,
    namespace: :string
  ]
  @default_opts [binary_id: false, device_code: false, namespace: "oauth"]
  @mix_task "ex_oauth2_provider.gen.migrations"

  @impl true
  def run(args) do
    ExOauth2Provider.no_umbrella!(@mix_task)

    args
    |> ExOauth2Provider.parse_options(@switches, @default_opts)
    |> parse()
    |> create_schema_files()
  end

  defp parse({config, _parsed, _invalid}), do: config

  defp create_schema_files(
         %{
           binary_id: binary_id,
           context_app: context_app,
           device_code: device_code,
           namespace: namespace
         } = config
       ) do
    context_app = context_app || ExOauth2Provider.otp_app()

    Schema.create_schema_files(
      context_app,
      namespace,
      binary_id: binary_id,
      device_code: device_code
    )
  end
end
