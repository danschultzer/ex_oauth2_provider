defmodule ExOauth2Provider.UtilsTest do
  use ExUnit.Case
  import ExOauth2Provider.Utils

  test "remove_empty_values/1" do
    assert remove_empty_values(%{one: nil, two: "", three: "test"}) == %{three: "test"}
  end
end
