defmodule ExOauth2Provider.Test.QueryHelpers do
  @moduledoc false

  import Ecto.Query
  alias Ecto.Changeset

  def change!(struct, changes) do
    struct
    |> Changeset.change(changes)
    |> ExOauth2Provider.repo.update!()
  end

  def get_by(module, attrs) do
    ExOauth2Provider.repo.get_by(module, attrs)
  end

  def get_latest_inserted(module) do
    ExOauth2Provider.repo.one(from x in module,
      order_by: [desc: x.id], limit: 1)
  end
end
