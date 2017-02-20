defmodule ExOauth2Provider.Plug.LoadResourceTest do
  @moduledoc false
  use ExOauth2Provider.TestCase
  use Plug.Test

  import ExOauth2Provider.Factory
  import ExOauth2Provider.PlugHelpers

  alias ExOauth2Provider.Plug.LoadResource
  alias ExOauth2Provider.OauthAccessToken
  alias ExOauth2Provider.Test.Repo

  setup do
    user = insert(:user)
    attrs = params_for(:access_token, %{resource_owner_id: user.id})
    {_, access_token} = Repo.insert(OauthAccessToken.create_changeset(%OauthAccessToken{}, attrs))

    {
      :ok,
      conn: conn(:get, "/"),
      user: user,
      access_token: access_token
    }
  end

  test "with a resource already set", context do
    conn = context.conn
    |> ExOauth2Provider.Plug.set_current_resource(context.user)
    |> run_plug(LoadResource)
    assert ExOauth2Provider.Plug.current_resource(conn).id == context.user.id
  end

  test "with no resource set and no token", context do
    conn = run_plug(context.conn, LoadResource)
    assert ExOauth2Provider.Plug.current_resource(conn) == nil
  end

  test "with no resource set and no association from token", context do
    access_token = Ecto.Changeset.change(context.access_token, resource_owner_id: nil)
      |> Repo.update!

    conn = context.conn
    |> ExOauth2Provider.Plug.set_current_token(access_token)
    |> run_plug(LoadResource)
    assert ExOauth2Provider.Plug.current_resource(conn) == nil
  end

  test "with no resource set and valid token", context do
    conn = context.conn
    |> ExOauth2Provider.Plug.set_current_token(context.access_token)
    |> run_plug(LoadResource)
    assert ExOauth2Provider.Plug.current_resource(conn).id == context.user.id
  end
end
