defmodule Mix.Tasks.ExOauth2Provider.Install do
  @shortdoc "Generates a new migration for the repo"

  @moduledoc """
  Generates migrations and schema module files.

        mix ex_oauth2_provider.install

  The repository must be set under `:ecto_repos` in the current app
  configuration or given via the `-r` option.

  By default, the migration will be generated to the
  "priv/YOUR_REPO/migrations" directory of the current application but it
  can be configured to be any subdirectory of `priv` by specifying the
  `:priv` key under the repository configuration.

  ## Arguments

    * `-r`, `--repo` - the repo to generate migration for
    * `--config-file` - the configuration file to update
    * `--resource-owner` - defines the resource owner, default is MyApp.Users.User
    * `--no-config` -- Don't append to your `config/config.exs` file
    * `--no-migrations` -- Don't add migrations
    * `--uuid` -- Use UUID for the following comma separated tables, use `all` if your database doesn't have auto incremental integer support
  """

  use Mix.Task

  alias Mix.{Ecto, Project}
  alias Mix.ExOauth2Provider.{Config, Migration}

  @config_file "config/config.exs"
  @switches    [resource_owner: :string, config_file: :string,
                config: :boolean, migrations: :boolean, uuid: :string]

  @doc false
  def run(args) do
    no_umbrella!()

    args
    |> parse_options_to_config()
    |> add_migrations_files(args)
    |> update_config()
  end

  defp parse_options_to_config(args) do
    {opts, _, _} = OptionParser.parse(args, switches: @switches)
    uuid_opts = parse_uuid_opts(Keyword.get(opts, :uuid, ""))

    %{
      config: Keyword.get(opts, :config, true),
      config_file: Keyword.get(opts, :config_file, @config_file),
      app_path: Project.app_path(),
      resource_owner: Keyword.get(opts, :resource_owner, "MyApp.Users.User"),
      migrations: Keyword.get(opts, :migrations, true),
      uuid: uuid_opts,
      repos: []
    }
  end

  defp parse_uuid_opts(string) when is_binary(string) do
    string
    |> String.split(",")
    |> parse_uuid_opts()
  end
  defp parse_uuid_opts(uuid_tables) do
    [:resource_owners, :oauth_access_grants, :oauth_access_tokens, :oauth_applications]
    |> Enum.map(&{&1, uuid?(&1, uuid_tables)})
    |> Enum.into(%{})
  end

  defp uuid?(_, ["all"]), do: true
  defp uuid?(table, uuid_tables), do: Enum.member?(uuid_tables, Atom.to_string(table))

  defp add_migrations_files(%{migrations: true} = config, args) do
    repos =
      args
      |> Ecto.parse_repo()
      |> Enum.map(&Ecto.ensure_repo(&1, args))
      |> Enum.map(&Map.put(config, :repo, &1))
      |> Enum.map(&Migration.create/1)

    %{config | repos: repos}
  end
  defp add_migrations_files(config, _args), do: config

  defp update_config(%{config: true} = config), do: Config.update(config)
  defp update_config(config), do: config

  defp no_umbrella! do
    if Project.umbrella?() do
      Mix.raise("mix ex_oauth2_provider.install can't be used in umbrella apps")
    end

    :ok
  end
end
