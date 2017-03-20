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

  test "changeset with blank redirect uri" do
    changeset = OauthApplication.changeset(%OauthApplication{}, %{redirect_uri: ""})
    assert changeset.errors[:redirect_uri] == {"Redirect URI cannot be blank", []}

    changeset = OauthApplication.changeset(%OauthApplication{}, %{redirect_uri: "\n \t "})
    assert changeset.errors[:redirect_uri] == {"Redirect URI cannot be blank", []}
  end

  test "changeset with redirect uri containing fragments" do
    changeset = OauthApplication.changeset(%OauthApplication{}, %{redirect_uri: "https://example.org/endpoint#test"})
    assert changeset.errors[:redirect_uri] == {"Redirect URI cannot contain fragments", []}
  end

  test "changeset with redirect uri missing scheme" do
    changeset = OauthApplication.changeset(%OauthApplication{}, %{redirect_uri: "example.org/endpoint"})
    assert changeset.errors[:redirect_uri] == {"Redirect URI has to be absolute", []}
  end

  test "changeset with redirect uri missing host" do
    changeset = OauthApplication.changeset(%OauthApplication{}, %{redirect_uri: "http://"})
    assert changeset.errors[:redirect_uri] == {"Redirect URI has to be absolute", []}
  end

  test "changeset with redirect uri with http" do
    changeset = OauthApplication.changeset(%OauthApplication{}, %{redirect_uri: "http://example.org/endpoint"})
    assert changeset.errors[:redirect_uri] == {"Redirect URI has to be https", []}
  end

  test "changeset with native redirect uri" do
    changeset = OauthApplication.create_changeset(%OauthApplication{}, %{resource_owner_id: 0, name: "Test", redirect_uri: ExOauth2Provider.native_redirect_uri})
    assert changeset.valid?
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
