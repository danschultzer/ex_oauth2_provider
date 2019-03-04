defmodule ExOauth2Provider.Plug.EnsureAuthenticatedTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.{Plug, Plug.EnsureAuthenticated}

  defmodule TestHandler do
    @moduledoc false

    def unauthenticated(conn, _) do
      assert conn.halted

      :unauthenticated
    end
  end

  setup do
    {:ok, conn: conn(:get, "/foo")}
  end

  describe "with valid access token doesn't require authentication" do
    setup context do
      application = Fixtures.application(Fixtures.resource_owner(), %{scopes: "app:read app:write"})
      access_token = Fixtures.access_token(Fixtures.resource_owner(), %{application: application, scopes: "app:read"})

      {:ok, Map.put(context, :access_token, access_token)}
    end

    test "with default key", %{conn: conn, access_token: access_token} do
      conn =
        conn
        |> Plug.set_current_access_token({:ok, access_token})
        |> EnsureAuthenticated.call(handler: TestHandler)

      refute conn == :unauthenticated
    end

    test "with custom key", %{conn: conn, access_token: access_token} do
      conn =
        conn
        |> Plug.set_current_access_token({:ok, access_token}, :secret)
        |> EnsureAuthenticated.call(handler: TestHandler, key: :secret)

      refute conn == :unauthenticated
    end
  end

  describe "without valid access token" do
    test "requires authentication with default key", %{conn: conn} do
      conn = EnsureAuthenticated.call(conn, handler: TestHandler)

      assert conn == :unauthenticated
    end

    test "requires authentication with custom key", %{conn: conn} do
      conn = EnsureAuthenticated.call(conn, handler: TestHandler, key: :secret)

      assert conn == :unauthenticated
    end
  end
end
