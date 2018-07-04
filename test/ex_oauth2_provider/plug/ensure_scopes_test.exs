defmodule ExOauth2Provider.Plug.EnsureScopeTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  alias Plug.Conn
  alias ExOauth2Provider.Test.PlugHelpers
  alias ExOauth2Provider.{Plug, Plug.EnsureScopes, Plug.ErrorHandler}

  defmodule TestHandler do
    @moduledoc false

    def unauthorized(conn, _) do
      conn
      |> Conn.assign(:ex_oauth2_provider_spec, :forbidden)
      |> Conn.send_resp(401, "Unauthorized")
    end
  end

  defp build_access_token(attrs) do
    %ExOauth2Provider.OauthAccessTokens.OauthAccessToken{token: "secret",
                                                         scopes: "read write"}
    |> Map.merge(attrs)
  end

  setup do
    access_token = build_access_token(%{scopes: "read write"})

    conn = conn(:get, "/foo")
    {:ok, %{conn: conn, access_token: access_token}}
  end

  test "init/1 sets the handler option to the module that's passed in" do
    %{handler: handler_opts} = EnsureScopes.init(handler: TestHandler)

    assert handler_opts == {TestHandler, :unauthorized}
  end

  test "init/1 defaults the handler option to ExOauth2Provider.Plug.ErrorHandler" do
    %{handler: handler_opts} = EnsureScopes.init(%{})

    assert handler_opts == {ErrorHandler, :unauthorized}
  end

  test "is valid when there's no scopes", %{conn: conn, access_token: access_token} do
    expected_conn = run_ensure_scopes_plug(conn, access_token, scopes: ~w())

    refute unauthorized?(expected_conn)
  end

  test "is valid when all scopes are present", %{conn: conn, access_token: access_token} do
    expected_conn = run_ensure_scopes_plug(conn, access_token, scopes: ~w(read write))

    refute unauthorized?(expected_conn)
  end

  test "is valid when the scope is present", %{conn: conn, access_token: access_token} do
    expected_conn = run_ensure_scopes_plug(conn, access_token, scopes: ~w(read))

    refute unauthorized?(expected_conn)
  end

  test "is invalid when all scopes are not present", %{conn: conn} do
    access_token = build_access_token(%{scopes: "read"})

    expected_conn = run_ensure_scopes_plug(conn, access_token, scopes: ~w(read write))

    assert unauthorized?(expected_conn)
  end

  test "is invalid when access token doesn't have any required scopes", %{conn: conn} do
    access_token = build_access_token(%{scopes: "other_read"})

    expected_conn = run_ensure_scopes_plug(conn, access_token, scopes: ~w(read write))

    assert unauthorized?(expected_conn)
  end

  test "is invalid when none of the one_of scopes is present", %{conn: conn} do
    access_token = build_access_token(%{scopes: "other_read"})

    expected_conn = run_ensure_scopes_plug(conn, access_token, one_of: [~w(other_write), ~w(read write)])

    assert unauthorized?(expected_conn)
  end

  test "is valid when at least one_of the scopes is present", %{conn: conn} do
    access_token = build_access_token(%{scopes: "other_read"})
    expected_conn = run_ensure_scopes_plug(conn, access_token, one_of: [~w(other_read), ~w(read write)])

    refute unauthorized?(expected_conn)
  end

  test "halts the connection", %{conn: conn, access_token: access_token} do
    expected_conn = run_ensure_scopes_plug(conn, access_token, scopes: ~w(read :write :other_read))

    assert expected_conn.halted
  end

  def unauthorized?(conn) do
    conn.assigns[:ex_oauth2_provider_spec] == :forbidden
  end

  defp run_ensure_scopes_plug(conn, access_token, args) do
    conn
    |> Plug.set_current_access_token({:ok, access_token})
    |> Conn.fetch_query_params()
    |> PlugHelpers.run_plug(EnsureScopes, Keyword.merge([handler: TestHandler], args))
  end
end
