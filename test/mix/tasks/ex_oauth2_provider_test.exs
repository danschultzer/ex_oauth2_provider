defmodule Mix.Tasks.ExOauth2ProviderTest do
  use ExUnit.Case

  alias Mix.Tasks.ExOauth2Provider

  test "provide a list of available ex_oauth2_provider mix tasks" do
    ExOauth2Provider.run([])

    assert_received {:mix_shell, :info, ["ExOauth2Provider v" <> _]}
    assert_received {:mix_shell, :info, ["mix ex_oauth2_provider.install" <> _]}
  end

  test "expects no arguments" do
    assert_raise Mix.Error, fn ->
      ExOauth2Provider.run(["invalid"])
    end
  end
end
