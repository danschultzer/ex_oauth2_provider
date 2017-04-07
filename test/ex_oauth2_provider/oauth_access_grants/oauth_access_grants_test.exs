defmodule ExOauth2Provider.OauthAccessGrantTest do
  import ExOauth2Provider.QueryHelper

  use ExOauth2Provider.TestCase
  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.OauthAccessGrants.OauthAccessGrant
  alias ExOauth2Provider.OauthApplications

  @valid_attrs    %{expires_in: 600, redirect_uri: "https://example.org/endpoint"}

  setup do
    user = ExOauth2Provider.Factory.insert(:user)
    {:ok, %{user: user, application: ExOauth2Provider.Factory.insert(:application, %{resource_owner: user})}}
  end

  test "get_token!/1", %{user: user} do
    {:ok, application} = OauthApplications.create_application(user, %{name: "App", redirect_uri: "https://example.org/endpoint"})
    assert %OauthApplications.OauthApplication{id: id} = OauthApplications.get_application!(application.uid)
    assert application.id == id
  end

  test "get_grant/1", %{user: user, application: application} do
    {:ok, grant} = OauthAccessGrants.create_grant(user, application, @valid_attrs)
    assert %OauthAccessGrants.OauthAccessGrant{id: id} = get_access_grant_by_code(grant.token)
    assert grant.id == id
  end

  test "create_grant/3 with valid attributes", %{user: user, application: application} do
    assert {:ok, %OauthAccessGrant{} = grant} = OauthAccessGrants.create_grant(user, application, @valid_attrs)
    assert grant.resource_owner == user
    assert grant.application == application
  end

  test "create_grant/2 adds random token", %{user: user, application: application} do
    {:ok, grant} = OauthAccessGrants.create_grant(user, application, @valid_attrs)
    {:ok, grant2} = OauthAccessGrants.create_grant(user, application, @valid_attrs)
    assert grant.token !== grant2.token
  end

  test "create_grant/2 with missing expires_in", %{application: application, user: user} do
    attrs = Map.merge(@valid_attrs, %{expires_in: nil})
    assert {:error, %Ecto.Changeset{errors: [expires_in: _]}} = OauthAccessGrants.create_grant(user, application, attrs)
  end

  test "create_grant/2 with missing redirect_uri", %{application: application, user: user} do
    attrs = Map.merge(@valid_attrs, %{redirect_uri: nil})
    assert {:error, %Ecto.Changeset{errors: [redirect_uri: _]}} = OauthAccessGrants.create_grant(user, application, attrs)
  end
end
