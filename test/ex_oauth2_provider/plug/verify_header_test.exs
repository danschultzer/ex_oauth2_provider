defmodule ExOauth2Provider.Plug.VerifyHeaderTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  alias ExOauth2Provider.Test.{Fixtures, PlugHelpers}
  alias ExOauth2Provider.{Plug, Plug.VerifyHeader}

  setup do
    {
      :ok,
      conn: conn(:get, "/"),
      access_token: Fixtures.access_token(Fixtures.resource_owner(), %{})
    }
  end

  test "with no access token at a default location", context do
    conn = PlugHelpers.run_plug(context.conn, VerifyHeader)
    refute Plug.authenticated?(conn)
    assert Plug.current_access_token(conn) == nil
  end

  test "with no access token at a specified location", context do
    conn = PlugHelpers.run_plug(context.conn, VerifyHeader, %{key: :secret})
    refute Plug.authenticated?(conn, :secret)
    assert Plug.current_access_token(conn, :secret) == nil
  end

  test "with a valid access token at the default location", context do
    conn = context.conn
           |> put_req_header("authorization", context.access_token.token)
           |> PlugHelpers.run_plug(VerifyHeader)

    assert Plug.authenticated?(conn)
    assert Plug.current_access_token(conn) == context.access_token
  end

  test "with a valid access token at a specified location", context do
    conn = context.conn
           |> put_req_header("authorization", context.access_token.token)
           |> PlugHelpers.run_plug(VerifyHeader, %{key: :secret})

    assert Plug.authenticated?(conn, :secret)
    assert Plug.current_access_token(conn, :secret) == context.access_token
  end

  test "with a realm specified", context do
    conn = context.conn
           |> put_req_header("authorization", "Bearer #{context.access_token.token}")
           |> PlugHelpers.run_plug(VerifyHeader, realm: "Bearer")

    assert Plug.authenticated?(conn)
    assert Plug.current_access_token(conn) == context.access_token
  end

  test "with a realm specified and multiple auth headers", context do
    another_access_token = Fixtures.access_token(Fixtures.resource_owner(), %{})

    conn = context.conn
           |> put_req_header("authorization", "Bearer #{context.access_token.token}")
           |> put_req_header("authorization", "Client #{another_access_token.token}")
           |> PlugHelpers.run_plug(VerifyHeader, realm: "Client")

    assert Plug.authenticated?(conn)
    assert Plug.current_access_token(conn) == another_access_token
  end

  test "pulls different tokens into different locations", context do
    another_access_token = Fixtures.access_token(Fixtures.resource_owner(), %{})

    # Can't use the put_req_header here since it overrides previous values
    the_conn = %{context.conn | req_headers: [
        {"authorization", "Bearer #{context.access_token.token}"},
        {"authorization", "Client #{another_access_token.token}"}
      ]
    }

    conn = the_conn
           |> PlugHelpers.run_plug(VerifyHeader, realm: "Bearer")
           |> PlugHelpers.run_plug(VerifyHeader, realm: "Client", key: :client)

    assert Plug.authenticated?(conn, :client)
    assert Plug.current_access_token(conn, :client) == another_access_token
    assert Plug.authenticated?(conn)
    assert Plug.current_access_token(conn) == context.access_token
  end
end
