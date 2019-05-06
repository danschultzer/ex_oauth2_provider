defmodule Mix.ExOauth2Provider.Migration do
  @moduledoc """
  Utilities module for ecto migrations in mix tasks.
  """
  alias Mix.Generator

  @doc """
  Creates a migration file for a repo.
  """
  @spec create_migration_file(atom(), binary(), binary()) :: any()
  def create_migration_file(repo, name, content) do
    base_name = "#{Macro.underscore(name)}.exs"
    path      =
      repo
      |> source_repo_priv()
      |> Path.join("migrations")
      |> maybe_create_directory()
    timestamp = timestamp(path)

    path
    |> ensure_unique(base_name, name)
    |> Path.join("#{timestamp}_#{base_name}")
    |> Generator.create_file(content)
  end

  defp maybe_create_directory(path) do
    Generator.create_directory(path)

    path
  end

  defp ensure_unique(path, base_name, name) do
    path
    |> Path.join("*_#{base_name}")
    |> Path.wildcard()
    |> case do
      [] -> path
      _  -> Mix.raise("migration can't be created, there is already a migration file with name #{name}.")
    end
  end

  defp timestamp(path, seconds \\ 0) do
    timestamp = gen_timestamp(seconds)

    path
    |> Path.join("#{timestamp}_*.exs")
    |> Path.wildcard()
    |> case do
      [] -> timestamp
      _  -> timestamp(path, seconds + 1)
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

  # TODO: Remove by 1.1.0 and only use Ecto 3.0
  defp source_repo_priv(repo) do
    mod = if Code.ensure_loaded?(Mix.EctoSQL), do: Mix.EctoSQL, else: Mix.Ecto

    mod.source_repo_priv(repo)
  end

  @template """
  defmodule <%= inspect migration.repo %>.Migrations.<%= migration.name %> do
    use Ecto.Migration

    def change do
  <%= for schema <- migration.schemas do %>
      create table(:<%= schema.table %><%= if schema.binary_id do %>, primary_key: false<% end %>) do
  <%= if schema.binary_id do %>      add :id, :binary_id, primary_key: true
  <% end %><%= for {k, v} <- schema.attrs do %>      add <%= inspect k %>, <%= inspect v %><%= schema.defaults[k] %>
  <% end %><%= for {_, i, _, s} <- schema.assocs do %>      add <%= if(String.ends_with?(inspect(i), "_id"), do: inspect(i), else: inspect(i) <> "_id") %>, references(<%= inspect(s) %>, on_delete: :nothing<%= if schema.binary_id do %>, type: :binary_id<% end %>)
  <% end %>
        timestamps()
      end
  <%= for index <- schema.indexes do %>
      <%= index %><% end %>
  <% end %>
    end
  end
  """

  alias ExOauth2Provider.{AccessGrants.AccessGrant, AccessTokens.AccessToken, Applications.Application}

  @schemas [{"applications", Application}, {"access_grants", AccessGrant}, {"access_tokens", AccessToken}]

  @spec gen(binary(), binary(), map()) :: binary()
  def gen(name, namespace, %{repo: repo} = config) do
    schemas =
      for {table, module} <- @schemas,
        do: schema(module, table, namespace, config)

    EEx.eval_string(@template, migration: %{repo: repo, name: name, schemas: schemas})
  end

  defp schema(module, table, namespace, %{binary_id: binary_id}) do
    attrs           =
      module.attrs()
      |> Kernel.++(attrs_from_assocs(module.assocs(), namespace))
      |> migration_attrs()
    defaults        = defaults(attrs)
    {assocs, attrs} = partition_attrs(attrs)
    table           = "#{namespace}_#{table}"
    indexes         = migration_indexes(module.indexes(), table)

    %{
      table: table,
      binary_id: binary_id,
      attrs: attrs,
      defaults: defaults,
      assocs: assocs,
      indexes: indexes
    }
  end

  defp attrs_from_assocs(assocs, namespace) do
    assocs
    |> Enum.map(&attr_from_assoc(&1, namespace))
    |> Enum.reject(&is_nil/1)
  end

  defp attr_from_assoc({:belongs_to, name, :users}, _namespace) do
    {String.to_atom("#{name}_id"), {:references, :users}}
  end
  defp attr_from_assoc({:belongs_to, name, table}, namespace) do
    {String.to_atom("#{name}_id"), {:references, String.to_atom("#{namespace}_#{table}")}}
  end
  defp attr_from_assoc({:belongs_to, name, table, _defaults}, namespace), do: attr_from_assoc({:belongs_to, name, table}, namespace)
  defp attr_from_assoc(_assoc, _opts), do: nil

  defp migration_attrs(attrs) do
    Enum.map(attrs, &to_migration_attr/1)
  end

  defp to_migration_attr({name, type}) do
    {name, type, ""}
  end
  defp to_migration_attr({name, type, []}) do
    to_migration_attr({name, type})
  end
  defp to_migration_attr({name, type, defaults}) do
    defaults = Enum.map_join(defaults, ", ", fn {k, v} -> "#{k}: #{inspect v}" end)

    {name, type, ", #{defaults}"}
  end

  defp defaults(attrs) do
    Enum.map(attrs, fn {key, _value, defaults} ->
      {key, defaults}
    end)
  end

  defp partition_attrs(attrs) do
    {assocs, attrs} =
      Enum.split_with(attrs, fn
        {_, {:references, _}, _} -> true
        _ -> false
      end)

    attrs  = Enum.map(attrs, fn {key_id, type, _defaults} -> {key_id, type} end)
    assocs =
      Enum.map(assocs, fn {key_id, {:references, source}, _} ->
        key = String.replace(Atom.to_string(key_id), "_id", "")
        {String.to_atom(key), key_id, nil, source}
      end)

    {assocs, attrs}
  end

  defp migration_indexes(indexes, table) do
    Enum.map(indexes, &to_migration_index(table, &1))
  end

  defp to_migration_index(table, {key_or_keys, true}),
    do: "create unique_index(:#{table}, #{inspect(List.wrap(key_or_keys))})"
end
