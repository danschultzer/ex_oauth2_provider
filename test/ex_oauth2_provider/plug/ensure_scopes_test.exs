defmodule ExOauth2Provider.Plug.EnsureScopeTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  import ExOauth2Provider.Factory
  import ExOauth2Provider.PlugHelpers

  alias ExOauth2Provider.Plug.EnsureScopes

  defmodule TestHandler do
    @moduledoc false

    def unauthorized(conn, _) do
      conn
      |> Plug.Conn.assign(:ex_oauth2_provider_spec, :forbidden)
      |> Plug.Conn.send_resp(401, "Unauthorized")
    end
  end

  setup do
    access_token = build(:access_token, %{scopes: "read write"})

    conn = conn(:get, "/foo")
    {:ok, %{conn: conn, access_token: access_token}}
  end

  test "init/1 sets the handler option to the module that's passed in" do
    %{handler: handler_opts} = EnsureScopes.init(handler: TestHandler)

    assert handler_opts == {TestHandler, :unauthorized}
  end

  test "init/1 defaults the handler option to ExOauth2Provider.Plug.ErrorHandler" do
    %{handler: handler_opts} = EnsureScopes.init %{}

    assert handler_opts == {ExOauth2Provider.Plug.ErrorHandler, :unauthorized}
  end

  test "is valid when there's no scopes", %{conn: conn, access_token: access_token} do
    expected_conn =
      conn
      |> ExOauth2Provider.Plug.set_current_token(access_token)
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsureScopes, scopes: ~w(), handler: TestHandler)

    refute unauthorized?(expected_conn)
  end

  test "is valid when all scopes are present", %{conn: conn, access_token: access_token} do
    expected_conn =
      conn
      |> ExOauth2Provider.Plug.set_current_token(access_token)
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsureScopes, scopes: ~w(read write), handler: TestHandler)

    refute unauthorized?(expected_conn)
  end

  test "is valid when the scope is present", %{conn: conn, access_token: access_token} do
    expected_conn =
      conn
      |> ExOauth2Provider.Plug.set_current_token(access_token)
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsureScopes, handler: TestHandler,
                  scopes: ~w(read))

    refute unauthorized?(expected_conn)
  end

  test "is invalid when all scopes are not present", %{conn: conn} do
    access_token = build(:access_token, %{scopes: "read"})

    expected_conn =
      conn
      |> ExOauth2Provider.Plug.set_current_token(access_token)
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsureScopes, handler: TestHandler,
                  scopes: ~w(read write))

    assert unauthorized?(expected_conn)
  end

  test "is invalid when access token doesn't have any required scopes", %{conn: conn} do
    access_token = build(:access_token, %{scopes: "other_read"})

    expected_conn =
      conn
      |> ExOauth2Provider.Plug.set_current_token(access_token)
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsureScopes, handler: TestHandler,
                  scopes: ~w(read write))

    assert unauthorized?(expected_conn)
  end

  test "is invalid when none of the one_of scopes is present", %{conn: conn} do
    access_token = build(:access_token, %{scopes: "other_read"})

    expected_conn =
      conn
      |> ExOauth2Provider.Plug.set_current_token(access_token)
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsureScopes, handler: TestHandler,
                  one_of: [~w(other_write), ~w(read write)])

    assert unauthorized?(expected_conn)
  end

  test "is valid when at least one_of the scopes is present", %{conn: conn} do
    access_token = build(:access_token, %{scopes: "other_read"})

    expected_conn =
      conn
      |> ExOauth2Provider.Plug.set_current_token(access_token)
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsureScopes, handler: TestHandler,
                  one_of: [~w(other_read), ~w(read write)])

    refute unauthorized?(expected_conn)
  end

  test "halts the connection", %{conn: conn, access_token: access_token} do
    expected_conn =
      conn
      |> ExOauth2Provider.Plug.set_current_token(access_token)
      |> Plug.Conn.fetch_query_params
      |> run_plug(EnsureScopes, handler: TestHandler,
                  scopes: ~w(read :write :other_read))

    assert expected_conn.halted
  end

  def unauthorized?(conn) do
    conn.assigns[:ex_oauth2_provider_spec] == :forbidden
  end
end
