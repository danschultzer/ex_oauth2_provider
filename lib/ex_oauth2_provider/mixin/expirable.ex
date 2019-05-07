defmodule ExOauth2Provider.Mixin.Expirable do
  @moduledoc false

  alias Ecto.Schema
  alias ExOauth2Provider.Schema, as: SchemaHelpers

  @doc """
  Filter expired data.

  ## Examples

      iex> filter_expired(%Data{expires_in: 7200, inserted_at: ~N[2017-04-04 19:21:22.292762], ...}}
      %Data{}

      iex> filter_expired(%Data{expires_in: 10, inserted_at: ~N[2017-04-04 19:21:22.292762], ...}}
      nil
  """
  @spec filter_expired(Schema.t()) :: Schema.t() | nil
  def filter_expired(data) do
    case is_expired?(data) do
      true  -> nil
      false -> data
    end
  end

  @doc """
  Checks if data has expired.

  ## Examples

      iex> is_expired?(%Data{expires_in: 7200, inserted_at: ~N[2017-04-04 19:21:22], ...}}
      false

      iex> is_expired?(%Data{expires_in: 10, inserted_at: ~N[2017-04-04 19:21:22], ...}}
      true

      iex> is_expired?(%Data{expires_in: nil}}
      false
  """
  @spec is_expired?(Schema.t() | nil) :: boolean()
  def is_expired?(nil), do: true
  def is_expired?(%{expires_in: nil, inserted_at: _}), do: false
  def is_expired?(%struct{expires_in: expires_in, inserted_at: inserted_at}) do
    now  = SchemaHelpers.__timestamp_for__(struct, :inserted_at)
    type = now.__struct__()

    inserted_at
    |> type.add(expires_in, :second)
    |> type.compare(now)
    |> Kernel.!=(:gt)
  end
end
