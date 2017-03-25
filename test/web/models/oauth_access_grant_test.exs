defmodule ExOauth2Provider.OauthAccessGrantTest do
  use ExOauth2Provider.TestCase
  import ExOauth2Provider.Factory
  alias ExOauth2Provider.OauthAccessGrant

  @valid_attrs %{resource_owner_id: 0, application_id: 0, expires_in: 600}

  test "create_changeset/2 with missing application" do
    changeset = OauthAccessGrant.create_changeset(%OauthAccessGrant{}, %{resource_owner_id: 0})
    refute changeset.valid?
  end

  test "create_changeset/2 with missing resource owner" do
    changeset = OauthAccessGrant.create_changeset(%OauthAccessGrant{}, %{application_id: 0})
    refute changeset.valid?
  end

  test "create_changeset/2 with valid attributes" do
    changeset = OauthAccessGrant.create_changeset(%OauthAccessGrant{}, @valid_attrs)
    assert changeset.valid?
  end

  test "create_changeset/2 adds random token" do
    changeset = OauthAccessGrant.create_changeset(%OauthAccessGrant{}, @valid_attrs)
    changeset2 = OauthAccessGrant.create_changeset(%OauthAccessGrant{}, @valid_attrs)
    assert changeset.changes.token != changeset2.changes.token
  end

  test "create_grant/1" do
    attrs = %{resource_owner_id: insert(:user).id,
      application_id: insert(:application, %{resource_owner_id: 0}).id,
      expires_in: 600}
    assert {:ok, %OauthAccessGrant{}} = OauthAccessGrant.create_grant(attrs)
  end
end
