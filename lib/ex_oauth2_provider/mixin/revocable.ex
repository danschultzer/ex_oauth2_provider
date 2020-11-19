defmodule ExOauth2Provider.Mixin.Revocable do
  @moduledoc false

  alias Ecto.{Changeset, Schema}
  alias ExOauth2Provider.Config
  alias ExOauth2Provider.Schema, as: SchemaHelpers

  @doc """
  Revoke data.

  ## Examples

      iex> revoke(data)
      {:ok, %Data{revoked_at: ~N[2017-04-04 19:21:22.292762], ...}}

      iex> revoke(invalid_data)
      {:error, %Ecto.Changeset{}}
  """
  @spec revoke(Schema.t(), keyword()) :: {:ok, Schema.t()} | {:error, Changeset.t()}
  def revoke(data, config \\ []) do
    data
    |> revoke_query()
    |> case do
      nil -> {:ok, data}
      query -> Config.repo(config).update(query)
    end
  end

  @doc """
  Same as `revoke/1` but raises error.
  """
  @spec revoke!(Schema.t(), keyword()) :: Schema.t() | no_return
  def revoke!(data, config \\ []) do
    data
    |> revoke_query()
    |> case do
      nil -> data
      query -> Config.repo(config).update!(query)
    end
  end

  defp revoke_query(%struct{revoked_at: nil} = data) do
    Changeset.change(data, revoked_at: SchemaHelpers.__timestamp_for__(struct, :revoked_at))
  end

  defp revoke_query(_data), do: nil

  @doc """
  Filter revoked data.

  ## Examples

      iex> filter_revoked(%Data{revoked_at: nil, ...}}
      %Data{}

      iex> filter_revoked(%Data{revoked_at: ~N[2017-04-04 19:21:22.292762], ...}}
      nil
  """
  @spec filter_revoked(Schema.t()) :: Schema.t() | nil
  def filter_revoked(data) do
    case is_revoked?(data) do
      true -> nil
      false -> data
    end
  end

  @doc """
  Checks if data has been revoked.

  ## Examples

      iex> is_revoked?(%Data{revoked_at: nil, ...}}
      false

      iex> is_revoked?(%Data{revoked_at: ~N[2017-04-04 19:21:22.292762], ...}}
      true
  """
  @spec is_revoked?(Schema.t()) :: boolean()
  def is_revoked?(%{revoked_at: nil}), do: false
  def is_revoked?(_), do: true
end
