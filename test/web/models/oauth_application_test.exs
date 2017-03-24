defmodule ExOauth2Provider.OauthApplicationTest do
  use ExOauth2Provider.TestCase
  alias ExOauth2Provider.OauthApplication

  @valid_attrs %{resource_owner_id: 0, name: "Application", redirect_uri: "https://example.org/endpoint"}
  @invalid_attrs %{}

  test "create_changeset with valid attributes" do
    changeset = OauthApplication.create_changeset(%OauthApplication{}, @valid_attrs)
    assert changeset.valid?
  end

  test "create_changeset with invalid attributes" do
    changeset = OauthApplication.create_changeset(%OauthApplication{}, @invalid_attrs)
    refute changeset.valid?
  end

  test "create_changeset adds random secret" do
    changeset = OauthApplication.create_changeset(%OauthApplication{}, @valid_attrs)
    changeset2 = OauthApplication.create_changeset(%OauthApplication{}, @valid_attrs)
    assert changeset.changes.secret != changeset2.changes.secret
  end

  test "create_changeset adds random uid" do
    changeset = OauthApplication.create_changeset(%OauthApplication{}, @valid_attrs)
    changeset2 = OauthApplication.create_changeset(%OauthApplication{}, @valid_attrs)
    assert changeset.changes.uid != changeset2.changes.uid
  end
end
