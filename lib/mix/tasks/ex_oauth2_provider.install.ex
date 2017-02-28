defmodule Mix.Tasks.ExOauth2Provider.Install do
  use Mix.Task

  import Macro, only: [camelize: 1]
  import Mix.Generator
  import Mix.Ecto

  @shortdoc "Generates a new migration for the repo"

  @moduledoc """
  Generates migrations.
  The repository must be set under `:ecto_repos` in the
  current app configuration or given via the `-r` option.
  ## Example
      mix ex_oauth2_provider.install
  By default, the migration will be generated to the
  "priv/YOUR_REPO/migrations" directory of the current application
  but it can be configured to be any subdirectory of `priv` by
  specifying the `:priv` key under the repository configuration.
  ## Command line options
    * `-r`, `--repo` - the repo to generate migration for
  """

  @doc false
  def run(args) do
    no_umbrella!("ex_oauth2_provider.install")
    repos = parse_repo(args)

    Enum.each repos, fn repo ->
      case OptionParser.parse(args) do
        {opts, [], _} ->
          ensure_repo(repo, args)
          path = Path.relative_to(migrations_path(repo), Mix.Project.app_path)
          create_directory path
          existing_migrations = to_string File.ls!(path)

          for {name, template} <- migrations do
            unless String.match? existing_migrations, ~r/\d{14}_#{name}\.exs/ do
              file = Path.join(path, "#{next_migration_number(existing_migrations)}_#{name}.exs")
              create_file file, EEx.eval_string(template, [mod: Module.concat([repo, Migrations, camelize(name)])])
            end
          end
      end
    end
  end

  defp next_migration_number(existing_migrations, pad_time \\ 0) do
    timestamp = NaiveDateTime.utc_now
      |> NaiveDateTime.add(pad_time, :second)
      |> NaiveDateTime.to_erl
      |> padded_timestamp

    if String.match? existing_migrations, ~r/#{timestamp}_.*\.exs/ do
      next_migration_number(existing_migrations, pad_time + 1)
    else
      timestamp
    end
  end

  defp padded_timestamp({{y, m, d}, {hh, mm, ss}}), do: "#{y}#{pad(m)}#{pad(d)}#{pad(hh)}#{pad(mm)}#{pad(ss)}"
  defp pad(i) when i < 10, do: << ?0, ?0 + i >>
  defp pad(i), do: to_string(i)

  @migrations [
    {"create_oauth_tables", """
    defmodule <%= inspect mod %> do
      use Ecto.Migration

      def change do
        create table(:oauth_access_tokens) do
          add :resource_owner_id, :integer
          add :token, :string
          add :refresh_token, :string
          add :expires_in, :integer
          add :revoked_at, :naive_datetime
          add :scopes, :string

          timestamps()
        end
        create unique_index(:oauth_access_tokens, [:token])
        create index(:oauth_access_tokens, [:resource_owner_id])
        create unique_index(:oauth_access_tokens, [:refresh_token])

      end
    end
    """}
  ]
  def migrations, do: @migrations
end
