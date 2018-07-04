defmodule ExOauth2Provider.Plug.EnsureAuthenticatedTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  alias ExOauth2Provider.Test.{Fixtures, PlugHelpers}
  alias Plug.Conn
  alias ExOauth2Provider.{Plug, Plug.EnsureAuthenticated, Plug.ErrorHandler}

  defmodule TestHandler do
    @moduledoc false

    def unauthenticated(conn, _) do
      conn
      |> Conn.assign(:ex_oauth2_provider_spec, :unauthenticated)
      |> Conn.send_resp(401, "Unauthenticated")
    end
  end

  setup do
    application = Fixtures.application(Fixtures.resource_owner(), %{scopes: "app:read app:write"})
    access_token = Fixtures.access_token(Fixtures.resource_owner(), %{application: application, scopes: "app:read"})
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
    assert handler_opts == {ErrorHandler, :unauthenticated}
  end

  test "doesn't call unauth when valid token for default key", context do
    ensured_conn = context.conn
                   |> Plug.set_current_access_token({:ok, context.access_token})
                   |> PlugHelpers.run_plug(EnsureAuthenticated, handler: TestHandler)

    refute must_authenticate?(ensured_conn)
  end

  test "doesn't call unauthenticated when valid token for key", context do
    ensured_conn = context.conn
                   |> Plug.set_current_access_token({:ok, context.access_token}, :secret)
                   |> PlugHelpers.run_plug(EnsureAuthenticated, handler: TestHandler, key: :secret)

    refute must_authenticate?(ensured_conn)
  end

  test "calls unauthenticated with no token for default key", context do
    ensured_conn = PlugHelpers.run_plug(context.conn, EnsureAuthenticated, handler: TestHandler)

    assert must_authenticate?(ensured_conn)
  end

  test "calls unauthenticated when no token for key", context do
    ensured_conn = PlugHelpers.run_plug(context.conn, EnsureAuthenticated, handler: TestHandler, key: :secret)

    assert must_authenticate?(ensured_conn)
  end

  test "it halts the connection", context do
    ensured_conn = PlugHelpers.run_plug(context.conn, EnsureAuthenticated, handler: TestHandler, key: :secret)

    assert ensured_conn.halted
  end

  defp must_authenticate?(conn) do
    conn.assigns[:ex_oauth2_provider_spec] == :unauthenticated
  end
end
