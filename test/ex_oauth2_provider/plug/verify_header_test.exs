defmodule ExOauth2Provider.Plug.VerifyHeaderTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  import ExOauth2Provider.Factory
  import ExOauth2Provider.PlugHelpers

  alias ExOauth2Provider.Plug.VerifyHeader

  setup do
    {
      :ok,
      conn: conn(:get, "/"),
      access_token: access_token_with_user()
    }
  end

  test "with no access token at a default location", context do
    conn = run_plug(context.conn, VerifyHeader)
    assert not ExOauth2Provider.Plug.authenticated?(conn)
    assert ExOauth2Provider.Plug.current_token(conn) == nil
  end

  test "with no access token at a specified location", context do
    conn = run_plug(context.conn, VerifyHeader, %{key: :secret})
    assert not ExOauth2Provider.Plug.authenticated?(conn, :secret)
    assert ExOauth2Provider.Plug.current_token(conn, :secret) == nil
  end

  test "with a valid access token at the default location", context do
    conn =
      context.conn
      |> put_req_header("authorization", context.access_token.token)
      |> run_plug(VerifyHeader)

    assert ExOauth2Provider.Plug.authenticated?(conn)
    assert ExOauth2Provider.Plug.current_token(conn) == context.access_token
  end

  test "with a valid access token at a specified location", context do
    conn =
      context.conn
      |> put_req_header("authorization", context.access_token.token)
      |> run_plug(VerifyHeader, %{key: :secret})

    assert ExOauth2Provider.Plug.authenticated?(conn, :secret)
    assert ExOauth2Provider.Plug.current_token(conn, :secret) == context.access_token
  end

  test "with a realm specified", context do
    conn =
      context.conn
      |> put_req_header("authorization", "Bearer #{context.access_token.token}")
      |> run_plug(VerifyHeader, realm: "Bearer")

    assert ExOauth2Provider.Plug.authenticated?(conn)
    assert ExOauth2Provider.Plug.current_token(conn) == context.access_token
  end

  test "with a realm specified and multiple auth headers", context do
    another_access_token = access_token_with_user()

    conn =
      context.conn
      |> put_req_header("authorization", "Bearer #{context.access_token.token}")
      |> put_req_header("authorization", "Client #{another_access_token.token}")
      |> run_plug(VerifyHeader, realm: "Client")

    assert ExOauth2Provider.Plug.authenticated?(conn)
    assert ExOauth2Provider.Plug.current_token(conn) == another_access_token
  end

  test "pulls different tokens into different locations", context do
    another_access_token = access_token_with_user()

    # Can't use the put_req_header here since it overrides previous values
    the_conn = %{context.conn | req_headers: [
        {"authorization", "Bearer #{context.access_token.token}"},
        {"authorization", "Client #{another_access_token.token}"}
      ]
    }

    conn = the_conn
           |> run_plug(VerifyHeader, realm: "Bearer")
           |> run_plug(VerifyHeader, realm: "Client", key: :client)

    assert ExOauth2Provider.Plug.authenticated?(conn, :client)
    assert ExOauth2Provider.Plug.current_token(conn, :client) == another_access_token
    assert ExOauth2Provider.Plug.authenticated?(conn)
    assert ExOauth2Provider.Plug.current_token(conn) == context.access_token
  end
end
