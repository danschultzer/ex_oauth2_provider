defmodule ExOauth2Provider.KeysTest do
  use ExUnit.Case
  alias ExOauth2Provider.Keys

  test "access_token/1" do
    assert Keys.access_token_key(:foo) == :ex_oauth2_provider_foo_access_token
  end

  test "base_key/1" do
    assert Keys.base_key(:foo) == :ex_oauth2_provider_foo
  end

  test "base_key/1 beginning with ex_oauth2_provider_" do
    assert Keys.base_key("ex_oauth2_provider_foo") == :ex_oauth2_provider_foo
  end
end
