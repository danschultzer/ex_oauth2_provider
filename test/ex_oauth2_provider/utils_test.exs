defmodule ExOauth2Provider.UtilTest do
  use ExUnit.Case
  alias ExOauth2Provider.Utils

  test "remove_empty_values/1" do
    assert Utils.remove_empty_values(%{one: nil, two: "", three: "test"}) == %{three: "test"}
  end

  test "generate_token/0 it generate random token" do
    token_1 = Utils.generate_token()
    token_2 = Utils.generate_token()

    refute token_1 == token_2
  end

  test "generate_token/1 it generate the token with custom length" do
    token1 = Utils.generate_token(%{size: 1})
    token2 = Utils.generate_token(%{size: 2})

    assert String.length(token1) < String.length(token2)
  end
end
