defmodule ExOauth2Provider.Plug.EnsureScopesTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  alias ExOauth2Provider.{Plug, Plug.EnsureScopes}
  alias Dummy.OauthAccessTokens.OauthAccessToken

  @default_scopes "read write"

  defmodule TestHandler do
    @moduledoc false

    def unauthorized(conn, _) do
      assert conn.halted

      :forbidden
    end
  end

  setup do
    {:ok, conn: conn(:get, "/foo")}
  end

  test "is valid when there's no scopes", %{conn: conn} do
    conn = run_plug(conn, @default_scopes, scopes: ~w())

    refute conn == :forbidden
  end

  test "is valid when all scopes are present", %{conn: conn} do
    conn = run_plug(conn, @default_scopes, scopes: ~w(read write))

    refute conn == :forbidden
  end

  test "is valid when the scope is present", %{conn: conn} do
    conn = run_plug(conn, @default_scopes, scopes: ~w(read))

    refute conn == :forbidden
  end

  test "is invalid when all scopes are not present", %{conn: conn} do
    conn = run_plug(conn, "read", scopes: ~w(read write))

    assert conn == :forbidden
  end

  test "is invalid when access token doesn't have any required scopes", %{conn: conn} do
    conn = run_plug(conn, "other_read", scopes: ~w(read write))

    assert conn == :forbidden
  end

  test "is invalid when none of the one_of scopes is present", %{conn: conn} do
    conn = run_plug(conn, "other_read", one_of: [~w(other_write), ~w(read write)])

    assert conn == :forbidden
  end

  test "is valid when at least one_of the scopes is present", %{conn: conn} do
    conn = run_plug(conn, "other_read", one_of: [~w(other_read), ~w(read write)])

    refute conn == :forbidden
  end

  defp run_plug(conn, scopes, opts) do
    access_token = %OauthAccessToken{token: "secret", scopes: scopes}
    opts         = Keyword.merge([handler: TestHandler], opts)

    conn
    |> Plug.set_current_access_token({:ok, access_token})
    |> EnsureScopes.call(opts)
  end
end
