defmodule ExOauth2Provider.Plug.VerifyHeaderTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.{Plug, Plug.VerifyHeader}

  setup do
    {:ok, conn: conn(:get, "/") }
  end

  test "with no access token at a default location", %{conn: conn} do
    opts = VerifyHeader.init([])
    conn = VerifyHeader.call(conn, opts)

    refute Plug.authenticated?(conn)
    assert Plug.current_access_token(conn) == nil
  end

  test "with no access token at a specified location", %{conn: conn} do
    opts = VerifyHeader.init(key: :secret)
    conn = VerifyHeader.call(conn, opts)

    refute Plug.authenticated?(conn, :secret)
    assert Plug.current_access_token(conn, :secret) == nil
  end

  describe "with valid access token" do
    setup context do
      access_token = Fixtures.access_token()

      {:ok, Map.put(context, :access_token, access_token)}
    end

    test "at the default location", %{conn: conn, access_token: access_token} do
      opts = VerifyHeader.init()
      conn =
        conn
        |> put_req_header("authorization", access_token.token)
        |> VerifyHeader.call(opts)

      assert Plug.authenticated?(conn)
      assert Plug.current_access_token(conn) == access_token
    end

    test "at a specified location", %{conn: conn, access_token: access_token} do
      opts = VerifyHeader.init(key: :secret)
      conn =
        conn
        |> put_req_header("authorization", access_token.token)
        |> VerifyHeader.call(opts)

      assert Plug.authenticated?(conn, :secret)
      assert Plug.current_access_token(conn, :secret) == access_token
    end

    test "with a realm specified", %{conn: conn, access_token: access_token} do
      opts = VerifyHeader.init(realm: "Bearer")
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> VerifyHeader.call(opts)

      assert Plug.authenticated?(conn)
      assert Plug.current_access_token(conn) == access_token
    end

    test "with a realm specified and multiple auth headers", %{conn: conn, access_token: access_token} do
      another_access_token = Fixtures.access_token()

      opts = VerifyHeader.init(realm: "Client")
      conn =
        conn
        |> put_req_header("authorization", "Bearer #{access_token.token}")
        |> put_req_header("authorization", "Client #{another_access_token.token}")
        |> VerifyHeader.call(opts)

      assert Plug.authenticated?(conn)
      assert Plug.current_access_token(conn) == another_access_token
    end

    test "pulls different tokens into different locations", %{conn: conn, access_token: access_token} do
      another_access_token = Fixtures.access_token()

      req_headers = [
        {"authorization", "Bearer #{access_token.token}"},
        {"authorization", "Client #{another_access_token.token}"}
      ]

      opts_1 = VerifyHeader.init(realm: "Bearer")
      opts_2 = VerifyHeader.init(realm: "Client", key: :client)
      conn =
        conn
        |> Map.put(:req_headers, req_headers)
        |> VerifyHeader.call(opts_1)
        |> VerifyHeader.call(opts_2)

      assert Plug.authenticated?(conn, :client)
      assert Plug.current_access_token(conn, :client) == another_access_token
      assert Plug.authenticated?(conn)
      assert Plug.current_access_token(conn) == access_token
    end
  end
end
