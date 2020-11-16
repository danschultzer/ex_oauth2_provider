defmodule ExOauth2Provider.Schema do
  @moduledoc """
  This module will permit dynamic App.Schema load.
  """

  alias ExOauth2Provider.Config

  defmacro __using__(config \\ []) do
    quote do
      @config unquote(config)
    end
  end

  @doc false
  defmacro fields(module, opts \\ []) do
    except = Keyword.get(opts, :except, [])

    quote do
      unquote(module).attrs()
      |> Enum.each(fn
        {name, type} when name not in unquote(except) ->
          field(name, type)

        {name, type, defaults} when name not in unquote(except) ->
          field(name, type, defaults)

        _ ->
          nil
      end)

      unquote(module).assocs()
      |> unquote(__MODULE__).__assocs_with_queryable__(@config)
      |> unquote(__MODULE__).__filter_new_assocs__(@ecto_assocs)
      |> Enum.each(fn
        {:belongs_to, name, queryable} when name not in unquote(except) ->
          belongs_to(name, queryable)

        {:belongs_to, name, queryable, defaults} when name not in unquote(except) ->
          belongs_to(name, queryable, defaults)

        {:has_many, name, queryable} when name not in unquote(except) ->
          has_many(name, queryable)

        {:has_many, name, queryable, defaults} when name not in unquote(except) ->
          has_many(name, queryable, defaults)

        _ ->
          nil
      end)
    end
  end

  @doc false
  def __assocs_with_queryable__(assocs, config) do
    Enum.map(assocs, fn
      {:belongs_to, name, table} ->
        {:belongs_to, name, table_to_queryable(config, table)}

      {:belongs_to, name, table, defaults} ->
        {:belongs_to, name, table_to_queryable(config, table), defaults}

      {:has_many, name, table} ->
        {:has_many, name, table_to_queryable(config, table)}

      {:has_many, name, table, defaults} ->
        {:has_many, name, table_to_queryable(config, table), defaults}
    end)
  end

  defp table_to_queryable(config, :access_grants), do: Config.access_grant(config)
  defp table_to_queryable(config, :access_tokens), do: Config.access_token(config)
  defp table_to_queryable(config, :applications), do: Config.application(config)
  defp table_to_queryable(config, :users), do: Config.resource_owner(config)

  @doc false
  def __filter_new_assocs__(assocs, existing_assocs) do
    Enum.reject(assocs, fn assoc ->
      Enum.any?(existing_assocs, &assocs_match?(elem(assoc, 0), elem(assoc, 1), &1))
    end)
  end

  defp assocs_match?(:has_many, name, {name, %Ecto.Association.Has{cardinality: :many}}), do: true
  defp assocs_match?(:belongs_to, name, {name, %Ecto.Association.BelongsTo{}}), do: true
  defp assocs_match?(_type, _name, _existing_assoc), do: false

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
