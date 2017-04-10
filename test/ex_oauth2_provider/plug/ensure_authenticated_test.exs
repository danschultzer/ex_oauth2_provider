defmodule ExOauth2Provider.Plug.EnsureAuthenticatedTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  import ExOauth2Provider.Test.Fixture
  import ExOauth2Provider.PlugHelpers

  alias ExOauth2Provider.Plug.EnsureAuthenticated

  defmodule TestHandler do
    @moduledoc false

    def unauthenticated(conn, _) do
      conn
      |> Plug.Conn.assign(:ex_oauth2_provider_spec, :unauthenticated)
      |> Plug.Conn.send_resp(401, "Unauthenticated")
    end
  end

  setup do
    application = fixture(:application, fixture(:user), %{scopes: "app:read app:write"})
    access_token = fixture(:access_token, fixture(:user), %{application: application, scopes: "app:read"})
    {
      :ok,
      conn: conn(:get, "/foo"),
      access_token: access_token
    }
  end

  test "init/1 sets the handler option to the module that's passed in" do
    %{handler: handler_opts} = EnsureAuthenticated.init(handler: TestHandler)
    assert handler_opts == {TestHandler, :unauthenticated}
  end

  test "init/1 with default options" do
    assert %{handler: handler_opts, key: :default} = EnsureAuthenticated.init %{}
    assert handler_opts == {ExOauth2Provider.Plug.ErrorHandler, :unauthenticated}
  end

  test "doesn't call unauth when valid token for default key", context do
    ensured_conn = context.conn
                   |> ExOauth2Provider.Plug.set_current_access_token({:ok, context.access_token})
                   |> run_plug(EnsureAuthenticated, handler: TestHandler)

    refute must_authenticate?(ensured_conn)
  end

  test "doesn't call unauthenticated when valid token for key", context do
    ensured_conn = context.conn
                   |> ExOauth2Provider.Plug.set_current_access_token({:ok, context.access_token}, :secret)
                   |> run_plug(EnsureAuthenticated, handler: TestHandler, key: :secret)

    refute must_authenticate?(ensured_conn)
  end

  test "calls unauthenticated with no token for default key", context do
    ensured_conn = run_plug(context.conn, EnsureAuthenticated, handler: TestHandler)

    assert must_authenticate?(ensured_conn)
  end

  test "calls unauthenticated when no token for key", context do
    ensured_conn = run_plug(context.conn, EnsureAuthenticated, handler: TestHandler, key: :secret)

    assert must_authenticate?(ensured_conn)
  end

  test "it halts the connection", context do
    ensured_conn = run_plug(context.conn, EnsureAuthenticated, handler: TestHandler, key: :secret)

    assert ensured_conn.halted
  end

  defp must_authenticate?(conn) do
    conn.assigns[:ex_oauth2_provider_spec] == :unauthenticated
  end
end
