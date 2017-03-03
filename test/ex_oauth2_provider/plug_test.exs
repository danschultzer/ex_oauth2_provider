defmodule ExOauth2Provider.PlugTest do
  use ExOauth2Provider.TestCase
  require Plug.Test
  use Plug.Test

  import ExOauth2Provider.Factory

  setup do
    {:ok, %{conn: conn(:post, "/")}}
  end

  test "authenticated?", context do
    refute ExOauth2Provider.Plug.authenticated?(context.conn)
    new_conn = ExOauth2Provider.Plug.set_current_token(
      context.conn,
      "secret"
    )
    assert ExOauth2Provider.Plug.authenticated?(new_conn)
  end

  test "authenticated? with a key", context do
    refute ExOauth2Provider.Plug.authenticated?(context.conn, :secret)
    new_conn = ExOauth2Provider.Plug.set_current_token(
      context.conn,
      "secret",
      :secret
    )
    assert ExOauth2Provider.Plug.authenticated?(new_conn, :secret)
  end

  test "current_resource with no key and no token", context do
    assert ExOauth2Provider.Plug.current_resource(context.conn) == nil
  end

  test "current_resource with key and no resource", context do
    assert ExOauth2Provider.Plug.current_resource(context.conn, :secret) == nil
  end

  test "current_resource with no key and with token", context do
    token = build(:access_token, resource_owner: build(:user))
    new_conn = ExOauth2Provider.Plug.set_current_token(context.conn, token)
    assert ExOauth2Provider.Plug.current_resource(new_conn) == token.resource_owner
  end

  test "current_resource with key and token", context do
    token = build(:access_token, resource_owner: build(:user))
    new_conn = ExOauth2Provider.Plug.set_current_token(
      context.conn,
      token,
      :secret
    )

    assert ExOauth2Provider.Plug.current_resource(new_conn, :secret) == token.resource_owner
  end

  test "set_current_token with no key", context do
    token = "token"
    new_conn = ExOauth2Provider.Plug.set_current_token(context.conn, token)
    assert ExOauth2Provider.Plug.current_token(new_conn) == "token"
  end

  test "set_current_token with key", context do
    token = "token"
    new_conn = ExOauth2Provider.Plug.set_current_token(context.conn, token, :secret)
    assert ExOauth2Provider.Plug.current_token(new_conn, :secret) == "token"
  end

  test "current_token with no key and no token", context do
    assert ExOauth2Provider.Plug.current_token(context.conn) == nil
  end

  test "current_token with no key and token", context do
    token = "token"
    new_conn = ExOauth2Provider.Plug.set_current_token(context.conn, token)
    assert ExOauth2Provider.Plug.current_token(new_conn) == token
  end

  test "current_token with key and token", context do
    token = "token"
    new_conn = ExOauth2Provider.Plug.set_current_token(context.conn, token, :secret)
    assert ExOauth2Provider.Plug.current_token(new_conn, :secret) == token
  end

  test "current_token with key and no token", context do
    assert ExOauth2Provider.Plug.current_token(context.conn, :secret) == nil
  end
end
