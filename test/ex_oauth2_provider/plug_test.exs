defmodule ExOauth2Provider.PlugTest do
  use ExOauth2Provider.TestCase
  require Plug.Test
  use Plug.Test

  setup do
    {:ok, %{conn: conn(:post, "/")}}
  end

  test "authenticated?/1", context do
    refute ExOauth2Provider.Plug.authenticated?(context.conn)
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:ok, "secret"})
    assert ExOauth2Provider.Plug.authenticated?(new_conn)
  end

  test "authenticated?/2", context do
    refute ExOauth2Provider.Plug.authenticated?(context.conn, :secret)
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:ok, "secret"}, :secret)
    assert ExOauth2Provider.Plug.authenticated?(new_conn, :secret)
  end

  test "current_resource_owner/1 with no resource", context do
    assert ExOauth2Provider.Plug.current_resource_owner(context.conn) == nil
  end

  test "current_resource_owner/1 with error", context do
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:error, :error})
    assert ExOauth2Provider.Plug.current_resource_owner(new_conn) == nil
  end

  test "current_resource_owner/1 with resource", context do
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:ok, %{resource_owner: "user"}})
    assert ExOauth2Provider.Plug.current_resource_owner(new_conn) == "user"
  end

  test "current_resource_owner/2 with no resource", context do
    assert ExOauth2Provider.Plug.current_resource_owner(context.conn, :secret) == nil
  end

  test "current_resource_owner/2 with resource", context do
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:ok, %{resource_owner: "user"}}, :secret)
    assert ExOauth2Provider.Plug.current_resource_owner(new_conn, :secret) == "user"
  end

  test "set_current_access_token/2", context do
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:ok, "token"})
    assert ExOauth2Provider.Plug.current_access_token(new_conn) == "token"
  end

  test "set_current_access_token/3", context do
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:ok, "token"}, :secret)
    assert ExOauth2Provider.Plug.current_access_token(new_conn, :secret) == "token"
  end

  test "current_access_token/1 with no token", context do
    assert ExOauth2Provider.Plug.current_access_token(context.conn) == nil
  end

  test "current_access_token/1 with token", context do
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:ok, "token"})
    assert ExOauth2Provider.Plug.current_access_token(new_conn) == "token"
  end

  test "current_access_token/1 with error", context do
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:error, :error})
    assert ExOauth2Provider.Plug.current_access_token(new_conn) == nil
  end

  test "current_access_token/2 with no token", context do
    assert ExOauth2Provider.Plug.current_access_token(context.conn, :secret) == nil
  end

  test "current_access_token/2 with token", context do
    new_conn = ExOauth2Provider.Plug.set_current_access_token(context.conn, {:ok, "token"}, :secret)
    assert ExOauth2Provider.Plug.current_access_token(new_conn, :secret) == "token"
  end
end
