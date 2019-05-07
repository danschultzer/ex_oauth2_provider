defmodule ExOauth2Provider.TestCase do
  @moduledoc false

  use ExUnit.CaseTemplate
  alias ExOauth2Provider.Test.Repo
  alias Ecto.Adapters.SQL.Sandbox

  setup do
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    :ok
  end
end
