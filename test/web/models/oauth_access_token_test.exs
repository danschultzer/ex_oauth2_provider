defmodule ExOauth2Provider.OauthAccessTokenTest do
  use ExOauth2Provider.TestCase
  import ExOauth2Provider.Factory
  alias ExOauth2Provider.OauthAccessToken

  @valid_attrs %{resource_owner_id: 0}
  @invalid_attrs %{}

  test "create_changeset with valid attributes" do
    changeset = OauthAccessToken.create_changeset(%OauthAccessToken{}, @valid_attrs)
    assert changeset.valid?
  end

  test "create_changeset with application" do
    application = insert(:application, %{resource_owner_id: 0})
    changeset = OauthAccessToken.create_changeset(%OauthAccessToken{}, %{resource_owner_id: 0, application_id: application.id})
    assert changeset.valid?
  end

  test "create_changeset with invalid attributes" do
    changeset = OauthAccessToken.create_changeset(%OauthAccessToken{}, @invalid_attrs)
    refute changeset.valid?
  end

  test "create_changeset adds random token" do
    changeset = OauthAccessToken.create_changeset(%OauthAccessToken{}, @valid_attrs)
    changeset2 = OauthAccessToken.create_changeset(%OauthAccessToken{}, @valid_attrs)
    assert changeset.changes.token != changeset2.changes.token
  end

  test "sets default scopes" do
    access_token = OauthAccessToken.create_changeset(%OauthAccessToken{}, %{})
    assert access_token.changes.scopes == "read,write"
  end

  test "is_expired true" do
    inserted_at = NaiveDateTime.utc_now |> NaiveDateTime.add(-2, :second)
    access_token = build(:access_token, %{expires_in: 1, inserted_at: inserted_at})
    assert OauthAccessToken.is_expired?(access_token)
  end

  test "is_expired false" do
    access_token = access_token_with_user(%{expires_in: 1})
    assert OauthAccessToken.is_expired?(access_token) == false

    access_token = access_token_with_user()
      |> update_access_token_inserted_at(-2)
    assert OauthAccessToken.is_expired?(access_token) == false
  end

  test "is_accessible true" do
    access_token = insert(:access_token, %{resource_owner_id: 0})
    assert OauthAccessToken.is_expired?(access_token) == false
  end

  test "is_accessible false when revoked" do
    access_token = access_token_with_user(%{revoked_at: NaiveDateTime.utc_now})
    assert OauthAccessToken.is_expired?(access_token) == false
  end

  test "is_accessible false when expired" do
    access_token = access_token_with_user(%{revoked_at: NaiveDateTime.utc_now})
    assert OauthAccessToken.is_expired?(access_token) == false
  end
end
