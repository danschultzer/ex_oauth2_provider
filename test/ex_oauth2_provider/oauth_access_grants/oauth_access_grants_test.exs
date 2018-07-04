defmodule ExOauth2Provider.OauthAccessGrantTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.Fixtures
  alias ExOauth2Provider.{OauthAccessGrants, OauthAccessGrants.OauthAccessGrant}

  @valid_attrs %{expires_in: 600, redirect_uri: "https://example.org/endpoint"}

  setup do
    user = Fixtures.resource_owner()
    {:ok, %{user: user, application: Fixtures.application(user, %{scopes: "public read"})}}
  end

  test "get_valid_grant/2", %{user: user, application: application} do
    {:ok, grant} = OauthAccessGrants.create_grant(user, application, @valid_attrs)

    assert %OauthAccessGrants.OauthAccessGrant{id: id} = OauthAccessGrants.get_active_grant_for(application, grant.token)
    assert id == grant.id

    different_application = Fixtures.application(user, %{uid: "2"})
    refute OauthAccessGrants.get_active_grant_for(different_application, grant.token)
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

    assert {:error, changeset} = OauthAccessGrants.create_grant(user, application, attrs)
    assert changeset.errors[:expires_in] == {"can't be blank", [validation: :required]}
  end

  test "create_grant/2 with missing redirect_uri", %{application: application, user: user} do
    attrs = Map.merge(@valid_attrs, %{redirect_uri: nil})

    assert {:error, changeset} = OauthAccessGrants.create_grant(user, application, attrs)
    assert changeset.errors[:redirect_uri] == {"can't be blank", [validation: :required]}
  end

  test "create_token/2 with invalid scopes", %{application: application, user: user} do
    attrs = Map.merge(@valid_attrs, %{scopes: "write"})

    assert {:error, changeset} = OauthAccessGrants.create_grant(user, application, attrs)
    assert changeset.errors[:scopes] == {"not in permitted scopes list: \"public read\"", []}
  end

  describe "with no application scopes" do
    setup %{user: user, application: application} do
      application = Map.merge(application, %{scopes: ""})
      %{user: user, application: application}
    end

    test "create_token/2 with invalid scopes", %{application: application, user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "invalid"})

      assert {:error, changeset} = OauthAccessGrants.create_grant(user, application, attrs)
      assert changeset.errors[:scopes] == {"not in permitted scopes list: [\"public\", \"read\", \"write\"]", []}
    end

    test "create_token/2", %{application: application, user: user} do
      attrs = Map.merge(@valid_attrs, %{scopes: "write"})

      assert {:ok, grant} = OauthAccessGrants.create_grant(user, application, attrs)
      assert grant.scopes == "write"
    end
  end
end
