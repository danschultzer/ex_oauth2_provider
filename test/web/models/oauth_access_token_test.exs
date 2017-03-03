defmodule ExOauth2Provider.OauthAccessTokenTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.OauthAccessToken

  import ExOauth2Provider.Factory
  alias ExOauth2Provider.OauthAccessToken

  @valid_attrs %{resource_owner_id: 1}
  @invalid_attrs %{}

  test "create_changeset with valid attributes" do
    changeset = OauthAccessToken.create_changeset(%OauthAccessToken{}, @valid_attrs)
    assert changeset.valid?
  end

  test "create_changeset with invalid attributes" do
    changeset = OauthAccessToken.create_changeset(%OauthAccessToken{}, @invalid_attrs)
    refute changeset.valid?
  end

  test "sets default scopes" do
    access_token = insert(:access_token)
    assert access_token.scopes == "read,write"
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
    access_token = insert(:access_token)
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
