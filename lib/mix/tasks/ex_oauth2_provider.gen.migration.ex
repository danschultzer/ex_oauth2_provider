defmodule Mix.Tasks.ExOauth2Provider.Gen.Migration do
  @shortdoc "Generates ex_oauth2_provider migration file"

  @moduledoc """
  Generates ex_oauth2_provider migration files.

      mix ex_oauth2_provider.gen.migrations -r MyApp.Repo

      mix ex_oauth2_provider.gen.migrations -r MyApp.Repo --namespace oauth2

  This generator will add the oauth2 migration file in `priv/repo/migrations`.

  The repository must be set under `:ecto_repos` in the current app
  configuration or given via the `-r` option.

  By default, the migration will be generated to the
  "priv/YOUR_REPO/migrations" directory of the current application but it
  can be configured to be any subdirectory of `priv` by specifying the
  `:priv` key under the repository configuration.

  ## Arguments

    * `-r`, `--repo` - the repo module
    * `--binary-id` - use binary id for primary key
    * `--namespace` - schema namespace to use, defaults to `oauth`
  """
  use Mix.Task

  alias Mix.{Ecto, ExOauth2Provider, ExOauth2Provider.Migration}

  @switches [binary_id: :boolean]
  @default_opts [binary_id: false]
  @mix_task "ex_oauth2_provider.gen.migrations"

  @impl true
  def run(args) do
    ExOauth2Provider.no_umbrella!(@mix_task)

    args
    |> ExOauth2Provider.parse_options(@switches, @default_opts)
    |> parse()
    |> create_migration_files(args)
  end

  defp parse({config, parsed, _invalid}) do
    namespace = case parsed do
      [namespace] -> namespace
      _           -> "oauth"
    end

    Map.put(config, :schema_namespace, namespace)
  end

  defp create_migration_files(config, args) do
    args
    |> Ecto.parse_repo()
    |> Enum.map(&Ecto.ensure_repo(&1, args))
    |> Enum.map(&Map.put(config, :repo, &1))
    |> Enum.each(&create_migration_files/1)
  end

  defp create_migration_files(%{repo: repo, schema_namespace: namespace} = config) do
    name         = "Create#{Macro.camelize(namespace)}Tables"
    content      = Migration.gen(name, namespace, config)

    Migration.create_migration_file(repo, name, content)
  end
end
