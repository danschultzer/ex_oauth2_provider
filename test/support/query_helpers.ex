defmodule ExOauth2Provider.Test.QueryHelpers do
  @moduledoc false

  alias ExOauth2Provider.Test.Repo
  import Ecto.Query
  alias Ecto.Changeset
  alias ExOauth2Provider.Schema

  def change!(struct, changes) do
    changes = convert_timestamps(changes)

    struct
    |> Changeset.change(changes)
    |> Repo.update!()
  end

  defp convert_timestamps(changes) do
    Enum.map(changes, &convert_timestamp/1)
  end

  defp convert_timestamp({key, %DateTime{} = value}), do: {key, %{value | microsecond: {0, 0}}}
  defp convert_timestamp(any), do: any

  def get_latest_inserted(module) do
    module
    |> order_by([x], desc: x.id)
    |> limit(1)
    |> Repo.one()
  end

  def timestamp(struct, type, opts \\ []) do
    now = Schema.__timestamp_for__(struct, type)

    opts
    |> Keyword.get(:seconds)
    |> case do
      nil -> now
      seconds -> now.__struct__.add(now, seconds, :second)
    end
  end
end
