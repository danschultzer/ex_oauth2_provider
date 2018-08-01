defmodule ExOauth2Provider.TestCase do
  @moduledoc false

  use ExUnit.CaseTemplate
  alias ExOauth2Provider.Test.{ConfigHelpers, Repo}
  alias Ecto.Adapters.SQL.Sandbox

  setup do
    ConfigHelpers.reset_config()
    :ok = Sandbox.checkout(Repo)
    Sandbox.mode(Repo, {:shared, self()})

    :ok
  end
end
