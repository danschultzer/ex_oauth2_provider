defmodule ExOauth2Provider.OauthAccessTokensTest do
  use ExOauth2Provider.TestCase
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessTokens.OauthAccessToken

  setup do
    user = ExOauth2Provider.Factory.insert(:user)
    {:ok, %{user: user, application: ExOauth2Provider.Factory.insert(:application, resource_owner: user)}}
  end

  test "get_token/1", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_token(token.token)
    assert id == token.id
  end

  test "get_most_recent_token/1", %{user: user, application: application} do
    {:ok, token1} = OauthAccessTokens.create_token(user, %{application: application})
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_most_recent_token(user, application)
    assert token1.id == id

    {:ok, token2} = OauthAccessTokens.create_token(user, %{application: application})
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_most_recent_token(user, application)
    assert token2.id == id

    inserted_at = NaiveDateTime.utc_now |> NaiveDateTime.add(1, :second)
    token1
    |> Ecto.Changeset.change(%{inserted_at: inserted_at})
    |> ExOauth2Provider.repo.update()
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_most_recent_token(user, application)
    assert id == token1.id
  end

  test "create_token/2 with valid attributes", %{user: user} do
    assert {:ok, %OauthAccessToken{}} = OauthAccessTokens.create_token(user)
  end

  test "create_token/2 with valid attributes and application", %{user: user, application: application} do
    assert {:ok, %OauthAccessToken{} = token} = OauthAccessTokens.create_token(user, %{application: application})
    assert token.application == application
  end

  test "create_token/2 with invalid attributes", %{user: user} do
    assert {:error, %Ecto.Changeset{}} = OauthAccessTokens.create_token(user, %{application: "invalid"})
  end

  test "create_token/2 adds random token", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    {:ok, token2} = OauthAccessTokens.create_token(user)
    assert token.token != token2.token
  end

  test "create_token/2 adds random refresh token", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    {:ok, token2} = OauthAccessTokens.create_token(user)
    assert token.refresh_token != token2.refresh_token
  end

  test "revoke_token/1 revokes token", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    assert {:ok, token} = OauthAccessTokens.revoke_token(token)
    assert OauthAccessTokens.token_revoked?(token) == true
  end

  test "revoke_token/1 doesn't revoke revoked tokens", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    token = Map.merge(token, %{revoked_at: NaiveDateTime.utc_now |> NaiveDateTime.add(-86400, :second)})
    {:ok, token2} = OauthAccessTokens.revoke_token(token)
    assert token2.revoked_at == token.revoked_at
  end

  test "token_revoked?/1#true" do
    assert OauthAccessTokens.token_revoked?(%OauthAccessToken{revoked_at: NaiveDateTime.utc_now})
  end

  test "token_revoked?/1#false" do
    refute OauthAccessTokens.token_revoked?(%OauthAccessToken{revoked_at: nil})
  end

  test "is_accessible?/1#true" do
    token = %OauthAccessToken{expires_in: 1, revoked_at: nil, inserted_at: NaiveDateTime.utc_now}
    assert OauthAccessTokens.is_accessible?(token)
  end

  test "is_accessible?/1#false when revoked" do
    token = %OauthAccessToken{expires_in: 1, revoked_at: NaiveDateTime.utc_now, inserted_at: NaiveDateTime.utc_now}
    refute OauthAccessTokens.is_accessible?(token)
  end

  test "is_accessible?/1#false when expired" do
    token = %OauthAccessToken{expires_in: 0, revoked_at: nil, inserted_at: NaiveDateTime.utc_now}
    refute OauthAccessTokens.is_accessible?(token)

    inserted_at = NaiveDateTime.utc_now |> NaiveDateTime.add(-2, :second)
    token = %OauthAccessToken{expires_in: 1, revoked_at: nil, inserted_at: inserted_at}
    refute OauthAccessTokens.is_accessible?(token)
  end
end
