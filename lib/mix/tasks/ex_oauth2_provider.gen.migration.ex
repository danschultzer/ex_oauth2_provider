defmodule Mix.Tasks.ExOauth2Provider.Gen.Migration do
  @shortdoc "Generates ExOauth2Provider migration file"

  @moduledoc """
  Generates migration file.

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
    * `--binary-id` - use binary id for primary keys
    * `--namespace` - namespace to prepend table and schema module name
  """
  use Mix.Task

  alias Mix.{Ecto, ExOauth2Provider, ExOauth2Provider.Migration}

  @switches [binary_id: :boolean, namespace: :string]
  @default_opts [binary_id: false, namespace: "oauth"]
  @mix_task "ex_oauth2_provider.gen.migrations"

  @impl true
  def run(args) do
    ExOauth2Provider.no_umbrella!(@mix_task)

    args
    |> ExOauth2Provider.parse_options(@switches, @default_opts)
    |> parse()
    |> create_migration_files(args)
  end

  defp parse({config, _parsed, _invalid}), do: config

  defp create_migration_files(config, args) do
    args
    |> Ecto.parse_repo()
    |> Enum.map(&ensure_repo(&1, args))
    |> Enum.map(&Map.put(config, :repo, &1))
    |> Enum.each(&create_migration_files/1)
  end

  defp create_migration_files(%{repo: repo, namespace: namespace} = config) do
    name = "Create#{Macro.camelize(namespace)}Tables"
    content = Migration.gen(name, namespace, config)

    Migration.create_migration_file(repo, name, content)
  end

  defp ensure_repo(repo, args) do
    Ecto.ensure_repo(repo, args ++ ~w(--no-deps-check))
  end
end
