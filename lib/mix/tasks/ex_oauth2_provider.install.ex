defmodule Mix.Tasks.ExOauth2Provider.Install do
  use Mix.Task

  alias Mix.Generator
  alias Mix.Ecto
  alias Mix.Project

  @shortdoc "Generates a new migration for the repo"

  @config_file         "config/config.exs"
  @switches            [resource_owner: :string, config_file: :string,
                        config: :boolean, migrations: :boolean,
                        uuid: :string]

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
    * `--config-file` - the configuration file to update
    * `--resource-owner` - defines the resource owner, default is MyApp.User
    * `--no-config` -- Don't append to your `config/config.exs` file.
    * `--no-migrations` -- Don't add migrations.
    * `--uuid` -- Use UUID for the following comma separated tables, use `all` if your database doesn't have auto incremental integer support
  """

  @doc false
  def run(args) do
    Ecto.no_umbrella!("ex_oauth2_provider.install")

    args
    |> parse_options_to_config()
    |> add_migrations_files()
    |> update_config()
  end

  defp parse_options_to_config(args) do
    repos = Ecto.parse_repo(args)
    Enum.each(repos, &Ecto.ensure_repo(&1, args))
    {opts, _, _} = OptionParser.parse(args, switches: @switches)
    uuid_opts = parse_uuid(Keyword.get(opts, :uuid, ""))

    %{
      config: Keyword.get(opts, :config, true),
      config_file: Keyword.get(opts, :config_file, @config_file),
      app_path: Project.app_path(),
      repos: repos,
      resource_owner: Keyword.get(opts, :resource_owner, "MyApp.User"),
      migrations: Keyword.get(opts, :migrations, true),
      uuid: uuid_opts
    }
  end

  defp parse_uuid(string) do
    uuid_tables = String.split(string, ",")

    [:resource_owners,
     :oauth_access_grants,
     :oauth_access_tokens,
     :oauth_applications]
    |> Enum.map(&{&1, uuid?(&1, uuid_tables)})
    |> Enum.into(%{})
  end

  defp uuid?(_, ["all"]), do: true
  defp uuid?(table, uuid_tables), do: Enum.member?(uuid_tables, Atom.to_string(table))

  defp add_migrations_files(%{migrations: true, repos: repos, app_path: app_path, uuid: uuid} = config) do
    Enum.each repos, fn repo ->
      path = Path.relative_to(Ecto.migrations_path(repo), app_path)
      Generator.create_directory(path)
      existing_migrations = to_string(File.ls!(path))

      for {name, template} <- migrations() do
        create_migration_file(repo, existing_migrations, name, path, template, uuid)
      end
    end

    config
  end
  defp add_migrations_files(config), do: config

  defp next_migration_number(existing_migrations, pad_time \\ 0) do
    timestamp = NaiveDateTime.utc_now()
                |> NaiveDateTime.add(pad_time, :second)
                |> NaiveDateTime.to_erl()
                |> padded_timestamp()

    if String.match? existing_migrations, ~r/#{timestamp}_.*\.exs/ do
      next_migration_number(existing_migrations, pad_time + 1)
    else
      timestamp
    end
  end

  defp create_migration_file(repo, existing_migrations, name, path, template, uuid) do
    unless String.match? existing_migrations, ~r/\d{14}_#{name}\.exs/ do
      file = Path.join(path, "#{next_migration_number(existing_migrations)}_#{name}.exs")
      module = Module.concat([repo, Migrations, Macro.camelize(name)])
      string = EEx.eval_string(template, [mod: module, uuid: uuid])

      Generator.create_file(file, string)
      Mix.shell.info "Migration file #{file} has been added."
    end
  end

  defp padded_timestamp({{y, m, d}, {hh, mm, ss}}), do: "#{y}#{pad(m)}#{pad(d)}#{pad(hh)}#{pad(mm)}#{pad(ss)}"
  defp pad(i) when i < 10, do: << ?0, ?0 + i >>
  defp pad(i), do: to_string(i)

  defp migrations do
    templates_path = :ex_oauth2_provider
                     |> Application.app_dir()
                     |> Path.join("priv/templates/migrations")

    for filename <- File.ls!(templates_path) do
      {String.slice(filename, 0..-5), File.read!(Path.join(templates_path, filename))}
    end
  end

  defp update_config(%{config: true} = config) do
    config
    |> update_config_string()
    |> write_config(config)
  end
  defp update_config(config), do: config
  defp update_config_string(config) do
    """
config :ex_oauth2_provider, ExOauth2Provider,
  repo: #{Enum.map(config[:repos], &to_string(&1))},
  resource_owner: #{config[:resource_owner]}
"""
  end

  defp write_config(string, %{config: true, config_file: config_file} = config) do
    case do_write_config(string, config_file) do
      {:error, reason} ->
        Mix.shell.info(reason)
        Enum.into [config_string: string, log_config?: true], config
      {:ok, reason} ->
        Mix.shell.info(reason)
        Enum.into [config_string: string, log_config?: false], config
    end
  end
  defp write_config(string, config), do: Enum.into([log_config?: true, config_string: string], config)

  defp do_write_config(string, config_file) do
    source = if File.exists?(config_file), do: File.read!(config_file), else: false
    cond do
      source == false ->
        {:error, "Could not find #{config_file}. Configuration was not added!"}
      String.contains? source, "config :ex_oauth2_provider, ExOauth2Provider" ->
        {:error, "Configuration was not added because one already exists!"}
      true ->
        File.write!(config_file, source <> "\n" <> string)
        {:ok, "Your config/config.exs file was updated."}
    end
  end
end
