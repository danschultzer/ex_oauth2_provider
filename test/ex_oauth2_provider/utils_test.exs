defmodule ExOauth2Provider.UtilTest do
  use ExUnit.Case
  import ExOauth2Provider.Utils

  test "remove_empty_values/1" do
    assert remove_empty_values(%{one: nil, two: "", three: "test"}) == %{three: "test"}
  end

  test "generate_token/0 it generate random token" do
    token_1 = generate_token()
    token_2 = generate_token()

    refute token_1 == token_2
  end

  test "generate_token/1 it generate the token with custom length" do
    assert String.length(generate_token(%{size: 1})) < String.length(generate_token(%{size: 2}))
  end
end
