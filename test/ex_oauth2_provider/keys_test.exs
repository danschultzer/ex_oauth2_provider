defmodule ExOauth2Provider.KeysTest do
  use ExUnit.Case

  test "access_token/1" do
    assert ExOauth2Provider.Keys.access_token_key(:foo) == :ex_oauth2_provider_foo_access_token
  end

  test "base_key/1" do
    assert ExOauth2Provider.Keys.base_key(:foo) == :ex_oauth2_provider_foo
  end

  test "base_key/1 beginning with ex_oauth2_provider_" do
    assert ExOauth2Provider.Keys.base_key("ex_oauth2_provider_foo") == :ex_oauth2_provider_foo
  end
end
