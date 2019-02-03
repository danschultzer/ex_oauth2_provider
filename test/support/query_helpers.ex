defmodule ExOauth2Provider.Test.QueryHelpers do
  @moduledoc false

  import Ecto.Query
  alias Ecto.Changeset

  def change!(struct, changes) do
    changes = convert_timestamps(changes)

    struct
    |> Changeset.change(changes)
    |> ExOauth2Provider.repo.update!()
  end

  def get_by(module, attrs) do
    ExOauth2Provider.repo.get_by(module, attrs)
  end

  def get_latest_inserted(module) do
    module
    |> order_by([x], desc: x.id)
    |> limit(1)
    |> ExOauth2Provider.repo.one()
  end

  defp convert_timestamps(changes) do
    Enum.map(changes, &convert_timestamp/1)
  end

  defp convert_timestamp({key, %NaiveDateTime{} = value}), do: {key, %{value | microsecond: {0, 0}}}
  defp convert_timestamp(any), do: any
end
