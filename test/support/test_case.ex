alias ExOauth2Provider.Test.Repo

defmodule ExOauth2Provider.TestCase do
  use ExUnit.CaseTemplate
  import ExOauth2Provider.ConfigHelpers

  setup do
    reset_config()
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
  end
end
