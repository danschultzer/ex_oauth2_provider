defmodule ExOauth2Provider.ConnCase do
  @moduledoc false

  use ExUnit.CaseTemplate

  alias Ecto.Adapters.SQL.Sandbox

  setup do
    :ok = Sandbox.checkout(Dummy.Repo)
    Sandbox.mode(Dummy.Repo, {:shared, self()})

    conn = Plug.Test.conn(:get, "/")

    {:ok, conn: conn}
  end
end
