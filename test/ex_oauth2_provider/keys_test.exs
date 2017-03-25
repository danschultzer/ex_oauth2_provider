defmodule ExOauth2Provider.KeysTest do
  use ExUnit.Case

  test "token key" do
    assert ExOauth2Provider.Keys.token_key(:foo) == :ex_oauth2_provider_foo_token
  end

  test "base_key with atom" do
    assert ExOauth2Provider.Keys.base_key(:foo) == :ex_oauth2_provider_foo
  end

  test "base_key beginning with ex_oauth2_provider_" do
    assert ExOauth2Provider.Keys.base_key("ex_oauth2_provider_foo") == :ex_oauth2_provider_foo
  end
end
