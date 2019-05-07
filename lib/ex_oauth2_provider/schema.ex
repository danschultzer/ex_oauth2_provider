defmodule ExOauth2Provider.Schema do
  @moduledoc """
  This module will permit dynamic App.Schema load.
  """

  alias ExOauth2Provider.Config

  defmacro __using__(_config) do
    quote do
    end
  end

  @doc false
  defmacro fields(module) do
    quote do
      Enum.each(unquote(module).attrs(), fn
        {name, type} ->
          field(name, type)

        {name, type, defaults} ->
          field(name, type, defaults)
      end)

      unquote(module).assocs()
      |> unquote(__MODULE__).__assocs_with_queryable__()
      |> Enum.each(fn
        {:belongs_to, name, queryable} ->
          belongs_to(name, queryable)

        {:belongs_to, name, queryable, defaults} ->
          belongs_to(name, queryable, defaults)

        {:has_many, name, queryable} ->
          has_many(name, queryable)

        {:has_many, name, queryable, defaults} ->
          has_many(name, queryable, defaults)
      end)
    end
  end

  @doc false
  def __assocs_with_queryable__(assocs) do
    Enum.map(assocs, fn
      {:belongs_to, name, table} -> {:belongs_to, name, table_to_queryable(table)}
      {:belongs_to, name, table, defaults} -> {:belongs_to, name, table_to_queryable(table), defaults}
      {:has_many, name, table} -> {:has_many, name, table_to_queryable(table)}
      {:has_many, name, table, defaults} -> {:has_many, name, table_to_queryable(table), defaults}
    end)
  end

  defp table_to_queryable(:access_grants), do: Config.access_grant()
  defp table_to_queryable(:access_tokens), do: Config.access_token()
  defp table_to_queryable(:applications), do: Config.application()
  defp table_to_queryable(:users), do: Config.resource_owner()

    @doc false
    def __timestamp_for__(struct, column) do
      type = struct.__schema__(:type, column)

      __timestamp__(type)
    end

    @doc false
  def __timestamp__(:naive_datetime) do
    %{NaiveDateTime.utc_now() | microsecond: {0, 0}}
  end
  def __timestamp__(:naive_datetime_usec) do
    NaiveDateTime.utc_now()
  end
  def __timestamp__(:utc_datetime) do
    DateTime.from_unix!(System.system_time(:second), :second)
  end
  def __timestamp__(:utc_datetime_usec) do
    DateTime.from_unix!(System.system_time(:microsecond), :microsecond)
  end
  def __timestamp__(type) do
    type.from_unix!(System.system_time(:microsecond), :microsecond)
  end
end
