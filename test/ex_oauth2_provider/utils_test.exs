defmodule ExOauth2Provider.UtilTest do
  use ExUnit.Case
  import ExOauth2Provider.Utils

  test "remove_empty_values/1" do
    assert remove_empty_values(%{one: nil, two: "", three: "test"}) == %{three: "test"}
  end

  test "generate_token/0 it generate random token" do
    assert generate_token() !== generate_token()
  end

  test "generate_token/1 it generate the token with custom length" do
    assert String.length(generate_token(%{size: 1})) < String.length(generate_token(%{size: 2}))
  end

  test "generate_token/1 it generate the token with custom generator" do
    generator = fn(string) -> Base.encode64(string) end
    assert String.length(generate_token(%{generator: generator})) < String.length(generate_token())
  end
end
