defmodule ExOauth2Provider.TestCase do
  @moduledoc false

  use ExUnit.CaseTemplate
  import ExOauth2Provider.ConfigHelpers
  alias ExOauth2Provider.Test.Repo

  setup do
    reset_config()
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
  end
end
