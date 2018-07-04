defmodule ExOauth2Provider.ScopesTest do
  use ExUnit.Case
  alias ExOauth2Provider.Scopes

  test "all?#true" do
    scopes = ["read", "write", "profile"]
    assert Scopes.all?(scopes, ["read", "profile"])
    assert Scopes.all?(scopes, ["write"])
    assert Scopes.all?(scopes, [])
  end

  test "all?#false" do
    scopes = ["read", "write", "profile"]
    refute Scopes.all?(scopes, ["read", "profile", "another_write"])
    refute Scopes.all?(scopes, ["read", "write", "profile", "another_write"])
  end

  test "equal?#true" do
    scopes = ["read", "write"]
    assert Scopes.equal?(scopes, ["read", "write"])
    assert Scopes.equal?(scopes, ["write", "read"])
  end

  test "equal?#false" do
    scopes = ["read", "write"]
    refute Scopes.equal?(scopes, ["read", "write", "profile"])
    refute Scopes.equal?(scopes, ["read"])
    refute Scopes.equal?(scopes, [])
  end

  test "to_list" do
    str = "user:read user:write global_write"
    assert Scopes.to_list(str) == ["user:read", "user:write", "global_write"]
    assert Scopes.to_list(nil) == []
  end

  test "to_string" do
    list = ["user:read", "user:write", "global_write"]
    assert Scopes.to_string(list) == "user:read user:write global_write"
  end
end
