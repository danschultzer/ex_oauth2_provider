defmodule ExOauth2Provider.OauthAccessTokensTest do
  use ExOauth2Provider.TestCase

  import ExOauth2Provider.Test.Fixture

  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessTokens.OauthAccessToken

  setup do
    user = fixture(:user)
    {:ok, %{user: user, application: fixture(:application, user, %{})}}
  end

  test "get_token/1", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_token(token.token)
    assert id == token.id
  end

  test "get_matching_token_for/1", %{user: user, application: application} do
    {:ok, token1} = OauthAccessTokens.create_token(user, %{application: application})
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, nil)
    assert token1.id == id

    {:ok, token2} = OauthAccessTokens.create_token(user, %{application: application})
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, nil)
    assert token2.id == id

    inserted_at = NaiveDateTime.utc_now |> NaiveDateTime.add(1, :second)
    token1
    |> Ecto.Changeset.change(inserted_at: inserted_at)
    |> ExOauth2Provider.repo.update
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, nil)
    assert id == token1.id

    token1
    |> Ecto.Changeset.change(scopes: "read write")
    |> ExOauth2Provider.repo.update
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "write read")
    assert id == token1.id

    assert nil == OauthAccessTokens.get_matching_token_for(user, application, "other_read")
    assert nil == OauthAccessTokens.get_matching_token_for(fixture(:user), application, nil)
  end

  test "get_active_tokens_for/1", %{user: user, application: application} do
    {:ok, token} = OauthAccessTokens.create_token(user, %{application: application})
    assert [%OauthAccessToken{}] = OauthAccessTokens.get_active_tokens_for(user)

    OauthAccessTokens.revoke(token)
    assert [] = OauthAccessTokens.get_active_tokens_for(user)

    assert [] == OauthAccessTokens.get_active_tokens_for(fixture(:user))
  end

  test "create_token/2 with valid attributes", %{user: user} do
    assert {:ok, %OauthAccessToken{}} = OauthAccessTokens.create_token(user)
  end

  test "create_token/2 with valid attributes and application", %{user: user, application: application} do
    assert {:ok, %OauthAccessToken{} = token} = OauthAccessTokens.create_token(user, %{application: application})
    assert token.application == application
  end

  test "create_token/2 adds random token", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    {:ok, token2} = OauthAccessTokens.create_token(user)
    assert token.token !== token2.token
  end

  test "create_token/2 adds random refresh token", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    {:ok, token2} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    assert token.refresh_token !== token2.refresh_token
  end

  test "create_token/2 doesn't add refresh token when disabled", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user, %{use_refresh_token: false})
    assert token.refresh_token == nil
  end

  test "find_or_create_token/2 gets existing token", %{user: user} do
    {:ok, token} = OauthAccessTokens.find_or_create_token(user)
    {:ok, token2} = OauthAccessTokens.find_or_create_token(user)
    assert token.id == token2.id
  end

  test "find_or_create_token/2 creates token when matching is revoked", %{user: user} do
    {:ok, token} = OauthAccessTokens.find_or_create_token(user)
    OauthAccessTokens.revoke(token)
    {:ok, token2} = OauthAccessTokens.find_or_create_token(user)
    assert token.id !== token2.id
  end

  test "find_or_create_token/2 creates token when matching has expired", %{user: user} do
    {:ok, token} = OauthAccessTokens.find_or_create_token(user, %{expires_in: 1})

    inserted_at = NaiveDateTime.utc_now |> NaiveDateTime.add(-token.expires_in, :second)
    token
    |> Ecto.Changeset.change(%{inserted_at: inserted_at})
    |> ExOauth2Provider.repo.update()

    {:ok, token2} = OauthAccessTokens.find_or_create_token(user)
    assert token.id !== token2.id
  end

  test "find_or_create_token/2 creates token when params are different", %{user: user} do
    {:ok, token} = OauthAccessTokens.find_or_create_token(user)

    {:ok, token2} = :user
    |> fixture
    |> OauthAccessTokens.find_or_create_token
    assert token.id !== token2.id

    Enum.each(%{application_id: 0,
                expires_in: 0,
                scopes: "public",
                scopes: nil}, fn({k, v}) ->
      {:ok, token2} = OauthAccessTokens.find_or_create_token(user, %{"#{k}": v})
      assert token.id !== token2.id
    end)
  end

  test "revoke/1 revokes token", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    assert {:ok, token} = OauthAccessTokens.revoke(token)
    assert OauthAccessTokens.is_revoked?(token) == true
  end

  test "revoke/1 doesn't revoke revoked tokens", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    token = Map.merge(token, %{revoked_at: NaiveDateTime.utc_now |> NaiveDateTime.add(-86400, :second)})
    {:ok, token2} = OauthAccessTokens.revoke(token)
    assert token2.revoked_at == token.revoked_at
  end

  test "is_revoked?/1#true" do
    assert OauthAccessTokens.is_revoked?(%OauthAccessToken{revoked_at: NaiveDateTime.utc_now})
  end

  test "is_revoked?/1#false" do
    refute OauthAccessTokens.is_revoked?(%OauthAccessToken{revoked_at: nil})
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
