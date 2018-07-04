defmodule ExOauth2Provider.OauthAccessTokensTest do
  use ExOauth2Provider.TestCase

  import ExOauth2Provider.Test.Fixture
  import ExOauth2Provider.ConfigHelpers

  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessTokens.OauthAccessToken

  setup do
    user = fixture(:user)
    {:ok, %{user: user, application: fixture(:application, user, %{})}}
  end

  test "get_by_token/1", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_by_token(token.token)
    assert id == token.id
  end

  test "get_by_refresh_token/2", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_by_refresh_token(token.refresh_token)
    assert id == token.id
  end

  test "get_by_previous_refresh_token_for/2", %{user: user} do
    {:ok, old_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    {:ok, new_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true, previous_refresh_token: old_token})
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_by_previous_refresh_token_for(new_token)
    assert id == old_token.id

    refute OauthAccessTokens.get_by_previous_refresh_token_for(old_token)

    {:ok, new_token_different_user} = OauthAccessTokens.create_token(fixture(:user), %{use_refresh_token: true, previous_refresh_token: old_token})
    refute OauthAccessTokens.get_by_previous_refresh_token_for(new_token_different_user)
  end

  test "get_by_previous_refresh_token_for/2 with application", %{user: user, application: application} do
    {:ok, old_token} = OauthAccessTokens.create_token(user, %{application: application, use_refresh_token: true})
    {:ok, new_token} = OauthAccessTokens.create_token(user, %{application: application, use_refresh_token: true, previous_refresh_token: old_token})
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_by_previous_refresh_token_for(new_token)
    assert id == old_token.id

    refute OauthAccessTokens.get_by_previous_refresh_token_for(old_token)

    {:ok, new_token_different_user} = OauthAccessTokens.create_token(fixture(:user), %{application: application, use_refresh_token: true, previous_refresh_token: old_token})
    refute OauthAccessTokens.get_by_previous_refresh_token_for(new_token_different_user)

    new_application = fixture(:application, user, %{uid: "new_app"})
    {:ok, new_token_different_app} = OauthAccessTokens.create_token(user, %{application: new_application, use_refresh_token: true, previous_refresh_token: old_token})
    refute OauthAccessTokens.get_by_previous_refresh_token_for(new_token_different_app)
  end

  test "get_matching_token_for/1", %{user: user, application: application} do
    {:ok, token1} = OauthAccessTokens.create_token(user, %{application: application})
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "public")
    assert token1.id == id

    {:ok, token2} = OauthAccessTokens.create_token(user, %{application: application})
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "public")
    assert token2.id == id

    inserted_at = NaiveDateTime.add(NaiveDateTime.utc_now(), 1, :second)
    update(token1, inserted_at: inserted_at)
    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "public")
    assert token1.id == id
  end

  test "get_matching_token_for/1 with different resource owner", %{user: user, application: application} do
    {:ok, _token} = OauthAccessTokens.create_token(user, %{application: application})
    refute OauthAccessTokens.get_matching_token_for(fixture(:user), application, nil)
  end

  test "get_matching_token_for/1 with scope", %{user: user, application: application} do
    {:ok, token1} = OauthAccessTokens.create_token(user, %{application: application, scopes: "public"})
    {:ok, token2} = OauthAccessTokens.create_token(user, %{application: application, scopes: "read write"})

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "public")
    assert token1.id == id

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "write read")
    assert token2.id == id

    refute OauthAccessTokens.get_matching_token_for(user, application, "other_read")
  end

  test "get_matching_token_for/1 with expired access token", %{user: user, application: application} do
    {:ok, token} = OauthAccessTokens.create_token(user, %{application: application, scopes: "public", expires_in: -1})
    refute OauthAccessTokens.get_matching_token_for(user, application, "public")

    update(token, expires_in: 1)
    assert %OauthAccessToken{} = OauthAccessTokens.get_matching_token_for(user, application, "public")
  end

  test "get_authorized_tokens_for/1", %{user: user, application: application} do
    {:ok, token} = OauthAccessTokens.create_token(user, %{application: application})
    assert [%OauthAccessToken{}] = OauthAccessTokens.get_authorized_tokens_for(user)

    update(token, expires_in: -1)
    assert [%OauthAccessToken{}] = OauthAccessTokens.get_authorized_tokens_for(user)

    OauthAccessTokens.revoke(token)
    assert [] = OauthAccessTokens.get_authorized_tokens_for(user)

    assert [] == OauthAccessTokens.get_authorized_tokens_for(fixture(:user))
  end

  test "create_token/2 with valid attributes", %{user: user} do
    assert {:ok, %OauthAccessToken{} = token} = OauthAccessTokens.create_token(user)
    assert token.resource_owner_id == user.id
    assert is_nil(token.application_id)
  end

  test "create_token/2 with resource owner and application", %{user: user, application: application} do
    {:ok, token} = OauthAccessTokens.create_token(user, %{application: application})
    assert token.resource_owner_id == user.id
    assert token.application_id == application.id
  end

  test "create_token/2 with application", %{application: application} do
    {:ok, token} = OauthAccessTokens.create_token(application)
    assert is_nil(token.resource_owner_id)
    assert token.application_id == application.id
  end

  test "create_token/2 adds random token", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    {:ok, token2} = OauthAccessTokens.create_token(user)
    assert token.token != token2.token
  end

  test "create_token/2 with custom access token generator", %{user: user} do
    set_config(:access_token_generator, {ExOauth2Provider.OauthAccessTokensTest, :access_token_generator})

    {:ok, token} = OauthAccessTokens.create_token(user, %{})
    assert token.token == "custom_generated-#{user.id}"
  end

  test "create_token/2 adds previous_refresh_token", %{user: user} do
    {:ok, old_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    {:ok, new_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true, previous_refresh_token: old_token})
    assert new_token.previous_refresh_token == old_token.refresh_token
  end

  test "create_token/2 adds random refresh token", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    {:ok, token2} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    assert token.refresh_token != token2.refresh_token
  end

  test "create_token/2 doesn't add refresh token when disabled", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user, %{use_refresh_token: false})
    assert token.refresh_token == nil
  end

  test "create_token/2 with no scopes", %{user: user} do
    assert {:ok, %OauthAccessToken{} = token} = OauthAccessTokens.create_token(user)
    assert token.scopes == "public"
  end

  test "create_token/2 with custom scopes", %{user: user} do
    assert {:ok, %OauthAccessToken{} = token} = OauthAccessTokens.create_token(user, %{scopes: "read"})
    assert token.scopes == "read"
  end

  test "create_token/2 with invalid scopes", %{user: user} do
    assert {:error, %Ecto.Changeset{}} = OauthAccessTokens.create_token(user, %{scopes: "invalid"})
  end

  describe "with application scopes" do
    setup %{user: user, application: application} do
       application = Map.merge(application, %{scopes: "public app:write app:read"})

       %{user: user, application: application}
    end

    test "create_token/2 with no scopes", %{user: user, application: application} do
      assert {:ok, %OauthAccessToken{} = token} = OauthAccessTokens.create_token(user, %{application: application})
      assert token.scopes == "public"
    end

    test "create_token/2 with custom scopes", %{user: user, application: application} do
      application = Map.merge(application, %{scopes: "app:read"})
      assert {:ok, %OauthAccessToken{} = token} = OauthAccessTokens.create_token(user, %{scopes: "app:read", application: application})
      assert token.scopes == "app:read"
    end

    test "create_token/2 with invalid scopes", %{user: user, application: application} do
      application = Map.merge(application, %{scopes: "app:read"})
      assert {:error, %Ecto.Changeset{}} = OauthAccessTokens.create_token(user, %{application: application, scopes: "app:write"})
    end
  end

  test "get_or_create_token/2 gets existing token", %{user: user} do
    {:ok, token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert is_nil(token.application_id)
    assert token.resource_owner_id == user.id

    {:ok, token2} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert token.id == token2.id

    update(token, scopes: "write read")
    {:ok, token3} = OauthAccessTokens.get_or_create_token(user, nil, "read write", %{})
    assert token.id == token3.id
  end

  test "get_or_create_token/2 with resource owner and application", %{user: user, application: application} do
    {:ok, token} = OauthAccessTokens.get_or_create_token(user, application, nil, %{})
    assert token.application_id == application.id
    assert token.resource_owner_id == user.id

    {:ok, token2} = OauthAccessTokens.get_or_create_token(user, application, nil, %{})
    assert token.id == token2.id

    update(token, scopes: "read write")
    {:ok, token3} = OauthAccessTokens.get_or_create_token(user, application, "read write", %{})
    assert token.id == token3.id
  end

  test "get_or_create_token/2 with application", %{application: application} do
    {:ok, token} = OauthAccessTokens.get_or_create_token(application, nil, %{})
    assert token.application_id == application.id
    assert is_nil(token.resource_owner_id)

    {:ok, token2} = OauthAccessTokens.get_or_create_token(application, nil, %{})
    assert token.id == token2.id
  end

  test "get_or_create_token/2 creates token when matching is revoked", %{user: user} do
    {:ok, token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    OauthAccessTokens.revoke(token)
    {:ok, token2} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert token.id != token2.id
  end

  test "get_or_create_token/2 creates token when matching has expired", %{user: user} do
    {:ok, token1} = OauthAccessTokens.create_token(user, %{expires_in: 1})
    {:ok, token2} = OauthAccessTokens.create_token(user, %{expires_in: 1})

    {:ok, token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert token.id == token2.id

    inserted_at = NaiveDateTime.add(NaiveDateTime.utc_now(), -token.expires_in, :second)
    update(token2, inserted_at: inserted_at)
    {:ok, token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert token.id == token1.id

    update(token1, inserted_at: inserted_at)
    {:ok, token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    refute token.id in [token1.id, token2.id]
  end

  test "get_or_create_token/2 creates token when params are different", %{user: user} do
    {:ok, token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})

    {:ok, token2} = OauthAccessTokens.get_or_create_token(fixture(:user), nil, nil, %{})
    assert token.id != token2.id

    application_id = (if System.get_env("UUID") == "all", do: "09b58e2b-8fff-4b8d-ba94-18a06dd4fc29", else: 0)
    {:ok, token3} = OauthAccessTokens.get_or_create_token(user, application_id, nil, %{})
    assert token.id != token3.id

    {:ok, token4} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{expires_in: 0})
    assert token.id != token4.id

    {:ok, token5} = OauthAccessTokens.get_or_create_token(user, nil, "read", %{})
    assert token.id != token5.id
  end

  test "revoke/1 revokes token", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    assert {:ok, token} = OauthAccessTokens.revoke(token)
    assert OauthAccessTokens.is_revoked?(token) == true
  end

  test "revoke/1 doesn't revoke revoked tokens", %{user: user} do
    {:ok, token} = OauthAccessTokens.create_token(user)
    token = Map.merge(token, %{revoked_at: NaiveDateTime.utc_now |> NaiveDateTime.add(-86_400, :second)})
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

  test "is_accessible?/1#false when never expires" do
    token = %OauthAccessToken{expires_in: nil, revoked_at: nil, inserted_at: NaiveDateTime.utc_now}
    assert OauthAccessTokens.is_accessible?(token)
  end

  test "is_accessible?/1#false when nil" do
    refute OauthAccessTokens.is_accessible?(nil)
  end

  defp update(token, changes) do
    token
    |> Ecto.Changeset.change(changes)
    |> ExOauth2Provider.repo.update()
  end

  def access_token_generator(values) do
    "custom_generated-#{values.resource_owner_id}"
  end
end
