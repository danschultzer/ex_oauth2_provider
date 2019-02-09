defmodule Mix.ExOauth2Provider.Migration do
  @moduledoc false

  alias Mix.Generator

  @spec create(%{repo: [atom()], app_path: binary(), uuid: map()}) :: atom()
  def create(%{repo: repo, app_path: app_path, uuid: uuid}) do
    path = Path.relative_to(migrations_path(repo), app_path)
    Generator.create_directory(path)
    existing_migration_files = to_string(File.ls!(path))

    for {name, template} <- migrations() do
      create_migration_file(repo, existing_migration_files, name, path, template, uuid)
    end

    repo
  end

  defp create_migration_file(repo, existing_migration_files, name, path, template, uuid) do
    unless String.match?(existing_migration_files, ~r/\d{14}_#{name}\.exs/) do
      timestamp = migration_timestamp(path)
      file      = Path.join(path, "#{timestamp}_#{name}.exs")
      module    = Module.concat([repo, Migrations, Macro.camelize(name)])
      content   = EEx.eval_string(template, [mod: module, uuid: uuid])

      Generator.create_file(file, content)
      Mix.shell.info "Migration file #{file} has been added."
    else
      Mix.shell.info "Not creating migration for #{name} because one already exists."
    end
  end

  defp migrations do
    templates_path =
      :ex_oauth2_provider
      |> Application.app_dir()
      |> Path.join("priv/templates/migrations")

    for filename <- File.ls!(templates_path) do
      {String.slice(filename, 0..-5), File.read!(Path.join(templates_path, filename))}
    end
  end

  defp migration_timestamp(path, seconds \\ 0) do
    timestamp = gen_timestamp(seconds)

    path
    |> Path.join("#{timestamp}_*.exs")
    |> Path.wildcard()
    |> case do
      [] -> timestamp
      _  -> migration_timestamp(path, seconds + 1)
    end
  end

  defp gen_timestamp(seconds) do
    %{year: y, month: m, day: d, hour: hh, minute: mm, second: ss} =
      DateTime.utc_now()
      |> DateTime.to_unix()
      |> Kernel.+(seconds)
      |> DateTime.from_unix!()

    "#{y}#{pad(m)}#{pad(d)}#{pad(hh)}#{pad(mm)}#{pad(ss)}"
  end

  defp pad(i) when i < 10, do: << ?0, ?0 + i >>
  defp pad(i), do: to_string(i)


  defp migrations_path(repo) do
    mod = if Code.ensure_loaded?(Mix.EctoSQL), do: Mix.EctoSQL, else: Mix.Ecto

    repo
    |> mod.source_repo_priv()
    |> Path.join("migrations")
  end
end
