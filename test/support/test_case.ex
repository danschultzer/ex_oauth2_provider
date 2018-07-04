defmodule ExOauth2Provider.TestCase do
  @moduledoc false

  use ExUnit.CaseTemplate
  alias ExOauth2Provider.Test.{ConfigHelpers, Repo}

  setup do
    ConfigHelpers.reset_config()
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(Repo)
    Ecto.Adapters.SQL.Sandbox.mode(Repo, {:shared, self()})
  end
end
