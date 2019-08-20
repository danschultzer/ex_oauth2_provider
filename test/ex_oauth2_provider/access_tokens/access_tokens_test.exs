defmodule ExOauth2Provider.AccessTokensTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.AccessTokens
  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}
  alias Dummy.OauthAccessTokens.OauthAccessToken

  setup do
    user = Fixtures.resource_owner()
    {:ok, %{user: user, application: Fixtures.application(resource_owner: user)}}
  end

  test "get_by_token/2", %{user: user} do
    assert {:ok, access_token} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)

    assert %OauthAccessToken{id: id} = AccessTokens.get_by_token(access_token.token, otp_app: :ex_oauth2_provider)
    assert id == access_token.id
  end

  test "get_by_refresh_token/2", %{user: user} do
    assert {:ok, access_token} = AccessTokens.create_token(user, %{use_refresh_token: true}, otp_app: :ex_oauth2_provider)

    assert %OauthAccessToken{id: id} = AccessTokens.get_by_refresh_token(access_token.refresh_token, otp_app: :ex_oauth2_provider)
    assert id == access_token.id
  end

  describe "get_by_previous_refresh_token_for/3" do
    test "with resource owner", %{user: user} do
      {:ok, old_access_token} = AccessTokens.create_token(user, %{use_refresh_token: true}, otp_app: :ex_oauth2_provider)
      {:ok, new_access_token} = AccessTokens.create_token(user, %{use_refresh_token: true, previous_refresh_token: old_access_token}, otp_app: :ex_oauth2_provider)

      assert %OauthAccessToken{id: id} = AccessTokens.get_by_previous_refresh_token_for(new_access_token, otp_app: :ex_oauth2_provider)
      assert id == old_access_token.id

      refute AccessTokens.get_by_previous_refresh_token_for(old_access_token, otp_app: :ex_oauth2_provider)

      {:ok, new_access_token_different_user} = AccessTokens.create_token(Fixtures.resource_owner(), %{use_refresh_token: true, previous_refresh_token: old_access_token}, otp_app: :ex_oauth2_provider)

      refute AccessTokens.get_by_previous_refresh_token_for(new_access_token_different_user, otp_app: :ex_oauth2_provider)
    end

    test "with application", %{user: user, application: application} do
      {:ok, old_access_token} = AccessTokens.create_token(user, %{application: application, use_refresh_token: true}, otp_app: :ex_oauth2_provider)
      {:ok, new_access_token} = AccessTokens.create_token(user, %{application: application, use_refresh_token: true, previous_refresh_token: old_access_token}, otp_app: :ex_oauth2_provider)

      assert %OauthAccessToken{id: id} = AccessTokens.get_by_previous_refresh_token_for(new_access_token, otp_app: :ex_oauth2_provider)
      assert id == old_access_token.id

      refute AccessTokens.get_by_previous_refresh_token_for(old_access_token, otp_app: :ex_oauth2_provider)

      {:ok, new_access_token_different_user} = AccessTokens.create_token(Fixtures.resource_owner(), %{application: application, use_refresh_token: true, previous_refresh_token: old_access_token}, otp_app: :ex_oauth2_provider)
      refute AccessTokens.get_by_previous_refresh_token_for(new_access_token_different_user, otp_app: :ex_oauth2_provider)

      new_application = Fixtures.application(resource_owner: user, uid: "new_app")
      {:ok, new_access_token_different_app} = AccessTokens.create_token(user, %{application: new_application, use_refresh_token: true, previous_refresh_token: old_access_token}, otp_app: :ex_oauth2_provider)

      refute AccessTokens.get_by_previous_refresh_token_for(new_access_token_different_app, otp_app: :ex_oauth2_provider)
    end
  end

  describe "get_token_for/4" do
    test "fetches for resource owner", %{user: user, application: application} do
      {:ok, access_token1} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)
      inserted_at = QueryHelpers.timestamp(OauthAccessToken, :inserted_at, seconds: -1)
      QueryHelpers.change!(access_token1, inserted_at: inserted_at)
      {:ok, access_token2} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)
      {:ok, _access_token_with_application} = AccessTokens.create_token(user, %{application: application}, otp_app: :ex_oauth2_provider)

      assert %OauthAccessToken{id: id} = AccessTokens.get_token_for(user, nil, nil, otp_app: :ex_oauth2_provider)
      assert id == access_token2.id

      refute AccessTokens.get_token_for(Fixtures.resource_owner(), nil, nil, otp_app: :ex_oauth2_provider)
    end

    test "with application", %{user: user, application: application} do
      {:ok, access_token1} = AccessTokens.create_token(user, %{application: application}, otp_app: :ex_oauth2_provider)
      inserted_at = QueryHelpers.timestamp(OauthAccessToken, :inserted_at, seconds: -1)
      QueryHelpers.change!(access_token1, inserted_at: inserted_at)
      {:ok, access_token2} = AccessTokens.create_token(user, %{application: application}, otp_app: :ex_oauth2_provider)
      {:ok, _access_token_without_application} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)

      assert %OauthAccessToken{id: id} = AccessTokens.get_token_for(user, application, nil, otp_app: :ex_oauth2_provider)
      assert id == access_token2.id
    end

    test "with scopes", %{user: user} do
      {:ok, access_token1} = AccessTokens.create_token(user, %{scopes: "public"}, otp_app: :ex_oauth2_provider)
      {:ok, access_token2} = AccessTokens.create_token(user, %{scopes: "read write"}, otp_app: :ex_oauth2_provider)

      assert %OauthAccessToken{id: id} = AccessTokens.get_token_for(user, nil, "public", otp_app: :ex_oauth2_provider)
      assert id == access_token1.id

      assert %OauthAccessToken{id: id} = AccessTokens.get_token_for(user, nil, "write read", otp_app: :ex_oauth2_provider)
      assert id == access_token2.id

      refute AccessTokens.get_token_for(user, nil, "other_read", otp_app: :ex_oauth2_provider)
    end

    test "filters revoked", %{user: user} do
      {:ok, access_token} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)
      assert AccessTokens.get_token_for(user, nil, nil, otp_app: :ex_oauth2_provider)

      AccessTokens.revoke(access_token)
      refute AccessTokens.get_token_for(user, nil, nil, otp_app: :ex_oauth2_provider)
    end

    test "filters expired", %{user: user} do
      {:ok, access_token} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)

      assert AccessTokens.get_token_for(user, nil, nil, otp_app: :ex_oauth2_provider)

      inserted_at = QueryHelpers.timestamp(access_token.__struct__, :inserted_at, seconds: -access_token.expires_in)
      QueryHelpers.change!(access_token, inserted_at: inserted_at)

      refute AccessTokens.get_token_for(user, nil, nil, otp_app: :ex_oauth2_provider)
    end
  end

  describe "get_application_token_for/3" do
    test "fetches", %{application: application} do
      {:ok, access_token1} = AccessTokens.create_application_token(application, %{}, otp_app: :ex_oauth2_provider)
      inserted_at = QueryHelpers.timestamp(OauthAccessToken, :inserted_at, seconds: -1)
      QueryHelpers.change!(access_token1, inserted_at: inserted_at)
      {:ok, access_token2} = AccessTokens.create_application_token(application, %{}, otp_app: :ex_oauth2_provider)

      assert %OauthAccessToken{id: id} = AccessTokens.get_application_token_for(application, nil, otp_app: :ex_oauth2_provider)
      assert id == access_token2.id

      refute AccessTokens.get_application_token_for(Fixtures.application(uid: "application-2"), nil, otp_app: :ex_oauth2_provider)
    end
  end

  test "get_authorized_tokens_for/2", %{user: user, application: application} do
    {:ok, access_token} = AccessTokens.create_token(user, %{application: application}, otp_app: :ex_oauth2_provider)

    assert [%OauthAccessToken{id: id}] = AccessTokens.get_authorized_tokens_for(user, otp_app: :ex_oauth2_provider)
    assert id == access_token.id

    QueryHelpers.change!(access_token, expires_in: -1)

    assert [%OauthAccessToken{id: id}] = AccessTokens.get_authorized_tokens_for(user, otp_app: :ex_oauth2_provider)
    assert id == access_token.id

    AccessTokens.revoke(access_token, otp_app: :ex_oauth2_provider)
    assert AccessTokens.get_authorized_tokens_for(user, otp_app: :ex_oauth2_provider) == []

    assert AccessTokens.get_authorized_tokens_for(Fixtures.resource_owner(), otp_app: :ex_oauth2_provider) == []
  end

  describe "create_token/3" do
    test "with valid attributes", %{user: user} do
      assert {:ok, access_token} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)
      assert access_token.resource_owner_id == user.id
      assert is_nil(access_token.application_id)
    end

    test "with resource owner and application", %{user: user, application: application} do
      {:ok, access_token} = AccessTokens.create_token(user, %{application: application}, otp_app: :ex_oauth2_provider)
      assert access_token.resource_owner_id == user.id
      assert access_token.application_id == application.id
    end

    test "adds random token", %{user: user} do
      {:ok, access_token} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)
      {:ok, access_token2} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)
      assert access_token.token != access_token2.token
    end

    test "with custom access token generator", %{user: user} do
      {:ok, access_token} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider, access_token_generator: &__MODULE__.access_token_generator/1)
      assert access_token.token == "custom_generated-#{user.id}"
    end

    test "adds previous_refresh_token", %{user: user} do
      {:ok, old_access_token} = AccessTokens.create_token(user, %{use_refresh_token: true}, otp_app: :ex_oauth2_provider)
      {:ok, new_access_token} = AccessTokens.create_token(user, %{use_refresh_token: true, previous_refresh_token: old_access_token}, otp_app: :ex_oauth2_provider)
      assert new_access_token.previous_refresh_token == old_access_token.refresh_token
    end

    test "adds random refresh token", %{user: user} do
      {:ok, access_token} = AccessTokens.create_token(user, %{use_refresh_token: true}, otp_app: :ex_oauth2_provider)
      {:ok, access_token2} = AccessTokens.create_token(user, %{use_refresh_token: true}, otp_app: :ex_oauth2_provider)
      assert access_token.refresh_token != access_token2.refresh_token
    end

    test "doesn't add refresh token when disabled", %{user: user} do
      {:ok, access_token} = AccessTokens.create_token(user, %{use_refresh_token: false}, otp_app: :ex_oauth2_provider)
      assert is_nil(access_token.refresh_token)
    end

    test "with no scopes", %{user: user} do
      assert {:ok, access_token} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)
      assert access_token.scopes == "public"
    end

    test "with custom scopes", %{user: user} do
      assert {:ok, access_token} = AccessTokens.create_token(user, %{scopes: "read"}, otp_app: :ex_oauth2_provider)
      assert access_token.scopes == "read"
    end

    test "with invalid scopes", %{user: user} do
      assert {:error, changeset} = AccessTokens.create_token(user, %{scopes: "invalid"}, otp_app: :ex_oauth2_provider)
      assert changeset.errors[:scopes] == {"not in permitted scopes list: [\"public\", \"read\", \"write\"]", []}
    end
  end

  describe "create_token/3 with application scopes" do
    setup %{user: user, application: application} do
       application = Map.merge(application, %{scopes: "public app:write app:read"})

       %{user: user, application: application}
    end

    test "with no scopes", %{user: user, application: application} do
      assert {:ok, access_token} = AccessTokens.create_token(user, %{application: application}, otp_app: :ex_oauth2_provider)
      assert access_token.scopes == "public"
    end

    test "with custom scopes", %{user: user, application: application} do
      application = Map.merge(application, %{scopes: "app:read"})
      assert {:ok, access_token} = AccessTokens.create_token(user, %{scopes: "app:read", application: application}, otp_app: :ex_oauth2_provider)
      assert access_token.scopes == "app:read"
    end

    test "with invalid scopes", %{user: user, application: application} do
      application = Map.merge(application, %{scopes: "app:read"})
      assert {:error, changeset} = AccessTokens.create_token(user, %{application: application, scopes: "app:write"}, otp_app: :ex_oauth2_provider)
      assert changeset.errors[:scopes] == {"not in permitted scopes list: \"app:read\"", []}
    end
  end

  test "create_application_token/3", %{application: application} do
    {:ok, access_token} = AccessTokens.create_application_token(application, %{}, otp_app: :ex_oauth2_provider)
    assert is_nil(access_token.resource_owner_id)
    assert access_token.application_id == application.id
  end

  describe "revoke/2" do
    test "revokes token", %{user: user} do
      {:ok, access_token} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)

      assert {:ok, access_token} = AccessTokens.revoke(access_token, otp_app: :ex_oauth2_provider)
      assert AccessTokens.is_revoked?(access_token) == true
    end

    test "doesn't revoke revoked tokens", %{user: user} do
      {:ok, access_token} = AccessTokens.create_token(user, %{}, otp_app: :ex_oauth2_provider)
      revoked_at = QueryHelpers.timestamp(OauthAccessToken, :revoked_at, seconds: -86_400)
      access_token = Map.merge(access_token, %{revoked_at: revoked_at})

      {:ok, access_token2} = AccessTokens.revoke(access_token, otp_app: :ex_oauth2_provider)
      assert access_token2.revoked_at == access_token.revoked_at
    end
  end

  test "is_revoked?/1" do
    assert AccessTokens.is_revoked?(%OauthAccessToken{revoked_at: QueryHelpers.timestamp(OauthAccessToken, :revoked_at)})
    refute AccessTokens.is_revoked?(%OauthAccessToken{revoked_at: nil})
  end

  describe "is_accessible?/1" do
    test "with active" do
      access_token = %OauthAccessToken{expires_in: 1, revoked_at: nil, inserted_at: QueryHelpers.timestamp(OauthAccessToken, :inserted_at)}
      assert AccessTokens.is_accessible?(access_token)
    end

    test "when revoked" do
      access_token = %OauthAccessToken{expires_in: 1, revoked_at: QueryHelpers.timestamp(OauthAccessToken, :revoked_at), inserted_at: QueryHelpers.timestamp(OauthAccessToken, :inserted_at)}
      refute AccessTokens.is_accessible?(access_token)
    end

    test "when expired" do
      access_token = %OauthAccessToken{expires_in: 0, revoked_at: nil, inserted_at: QueryHelpers.timestamp(OauthAccessToken, :inserted_at)}
      refute AccessTokens.is_accessible?(access_token)

      inserted_at = QueryHelpers.timestamp(OauthAccessToken, :inserted_at, seconds: -2)
      access_token = %OauthAccessToken{expires_in: 1, revoked_at: nil, inserted_at: inserted_at}
      refute AccessTokens.is_accessible?(access_token)
    end

    test "when never expires" do
      access_token = %OauthAccessToken{expires_in: nil, revoked_at: nil, inserted_at: QueryHelpers.timestamp(OauthAccessToken, :inserted_at)}
      assert AccessTokens.is_accessible?(access_token)
    end

    test "when nil" do
      refute AccessTokens.is_accessible?(nil)
    end
  end

  def access_token_generator(opts) do
    "custom_generated-#{opts[:resource_owner_id]}"
  end
end
