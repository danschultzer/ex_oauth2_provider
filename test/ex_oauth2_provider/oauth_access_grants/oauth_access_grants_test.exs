defmodule ExOauth2Provider.OauthAccessGrantTest do
  use ExOauth2Provider.TestCase

  import ExOauth2Provider.Test.QueryHelper
  import ExOauth2Provider.Test.Fixture

  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.OauthAccessGrants.OauthAccessGrant

  @valid_attrs    %{expires_in: 600, redirect_uri: "https://example.org/endpoint"}

  setup do
    user = fixture(:user)
    {:ok, %{user: user, application: fixture(:application, user, %{scopes: "public read"})}}
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
    assert grant.scopes == "public"
  end

  test "create_grant/2 adds random token", %{user: user, application: application} do
    {:ok, grant} = OauthAccessGrants.create_grant(user, application, @valid_attrs)
    {:ok, grant2} = OauthAccessGrants.create_grant(user, application, @valid_attrs)
    assert grant.token != grant2.token
  end

  test "create_grant/2 with missing expires_in", %{application: application, user: user} do
    attrs = Map.merge(@valid_attrs, %{expires_in: nil})
    assert {:error, %Ecto.Changeset{errors: [expires_in: _]}} = OauthAccessGrants.create_grant(user, application, attrs)
  end

  test "create_grant/2 with missing redirect_uri", %{application: application, user: user} do
    attrs = Map.merge(@valid_attrs, %{redirect_uri: nil})
    assert {:error, %Ecto.Changeset{errors: [redirect_uri: _]}} = OauthAccessGrants.create_grant(user, application, attrs)
  end

  test "create_token/2 with invalid scopes", %{application: application, user: user} do
    attrs = Map.merge(@valid_attrs, %{scopes: "write"})
    assert {:error, %Ecto.Changeset{}} = OauthAccessGrants.create_grant(user, application, attrs)
  end

  describe "with no application scopes" do
    setup %{user: user, application: application} do
      application = Map.merge(application, %{scopes: ""})
      %{user: user, application: application}
    end

    test "create_token/2 with invalid scopes", %{application: application, user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "invalid"})
      assert {:error, %Ecto.Changeset{}} = OauthAccessGrants.create_grant(user, application, attrs)
    end

    test "create_token/2", %{application: application, user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "write"})
      assert {:ok, %OauthAccessGrant{} = grant} = OauthAccessGrants.create_grant(user, application, attrs)
      assert grant.scopes == "write"
    end
  end
end
