defmodule ExOauth2Provider.OauthAccessTokensTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.{ConfigHelpers, Fixtures}
  alias ExOauth2Provider.{OauthAccessTokens, OauthAccessTokens.OauthAccessToken}

  setup do
    user = Fixtures.resource_owner()
    {:ok, %{user: user, application: Fixtures.application(user, %{})}}
  end

  test "get_by_token/1", %{user: user} do
    assert {:ok, access_token} = OauthAccessTokens.create_token(user)

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_by_token(access_token.token)
    assert id == access_token.id
  end

  test "get_by_refresh_token/2", %{user: user} do
    assert {:ok, access_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_by_refresh_token(access_token.refresh_token)
    assert id == access_token.id
  end

  test "get_by_previous_refresh_token_for/2", %{user: user} do
    {:ok, old_access_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    {:ok, new_access_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true, previous_refresh_token: old_access_token})

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_by_previous_refresh_token_for(new_access_token)
    assert id == old_access_token.id

    refute OauthAccessTokens.get_by_previous_refresh_token_for(old_access_token)

    {:ok, new_access_token_different_user} = OauthAccessTokens.create_token(Fixtures.resource_owner(), %{use_refresh_token: true, previous_refresh_token: old_access_token})

    refute OauthAccessTokens.get_by_previous_refresh_token_for(new_access_token_different_user)
  end

  test "get_by_previous_refresh_token_for/2 with application", %{user: user, application: application} do
    {:ok, old_access_token} = OauthAccessTokens.create_token(user, %{application: application, use_refresh_token: true})
    {:ok, new_access_token} = OauthAccessTokens.create_token(user, %{application: application, use_refresh_token: true, previous_refresh_token: old_access_token})

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_by_previous_refresh_token_for(new_access_token)
    assert id == old_access_token.id

    refute OauthAccessTokens.get_by_previous_refresh_token_for(old_access_token)

    {:ok, new_access_token_different_user} = OauthAccessTokens.create_token(Fixtures.resource_owner(), %{application: application, use_refresh_token: true, previous_refresh_token: old_access_token})
    refute OauthAccessTokens.get_by_previous_refresh_token_for(new_access_token_different_user)

    new_application = Fixtures.application(user, %{uid: "new_app"})
    {:ok, new_access_token_different_app} = OauthAccessTokens.create_token(user, %{application: new_application, use_refresh_token: true, previous_refresh_token: old_access_token})

    refute OauthAccessTokens.get_by_previous_refresh_token_for(new_access_token_different_app)
  end

  test "get_matching_token_for/1", %{user: user, application: application} do
    {:ok, access_token1} = OauthAccessTokens.create_token(user, %{application: application})

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "public")
    assert id == access_token1.id

    {:ok, access_token2} = OauthAccessTokens.create_token(user, %{application: application})

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "public")
    assert id == access_token2.id

    update(access_token1, inserted_at: NaiveDateTime.add(NaiveDateTime.utc_now(), 1, :second))

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "public")
    assert id == access_token1.id
  end

  test "get_matching_token_for/1 with different resource owner", %{user: user, application: application} do
    {:ok, _access_token} = OauthAccessTokens.create_token(user, %{application: application})

    refute OauthAccessTokens.get_matching_token_for(Fixtures.resource_owner(), application, nil)
  end

  test "get_matching_token_for/1 with scope", %{user: user, application: application} do
    {:ok, access_token1} = OauthAccessTokens.create_token(user, %{application: application, scopes: "public"})
    {:ok, access_token2} = OauthAccessTokens.create_token(user, %{application: application, scopes: "read write"})

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "public")
    assert id == access_token1.id

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "write read")
    assert id == access_token2.id

    refute OauthAccessTokens.get_matching_token_for(user, application, "other_read")
  end

  test "get_matching_token_for/1 with expired access token", %{user: user, application: application} do
    {:ok, access_token} = OauthAccessTokens.create_token(user, %{application: application, scopes: "public", expires_in: -1})

    refute OauthAccessTokens.get_matching_token_for(user, application, "public")

    update(access_token, expires_in: 1)

    assert %OauthAccessToken{id: id} = OauthAccessTokens.get_matching_token_for(user, application, "public")
    assert id == access_token.id
  end

  test "get_authorized_tokens_for/1", %{user: user, application: application} do
    {:ok, access_token} = OauthAccessTokens.create_token(user, %{application: application})

    assert [%OauthAccessToken{id: id}] = OauthAccessTokens.get_authorized_tokens_for(user)
    assert id == access_token.id

    update(access_token, expires_in: -1)

    assert [%OauthAccessToken{id: id}] = OauthAccessTokens.get_authorized_tokens_for(user)
    assert id == access_token.id

    OauthAccessTokens.revoke(access_token)
    assert OauthAccessTokens.get_authorized_tokens_for(user) == []

    assert OauthAccessTokens.get_authorized_tokens_for(Fixtures.resource_owner()) == []
  end

  test "create_token/2 with valid attributes", %{user: user} do
    assert {:ok, access_token} = OauthAccessTokens.create_token(user)
    assert access_token.resource_owner_id == user.id
    assert is_nil(access_token.application_id)
  end

  test "create_token/2 with resource owner and application", %{user: user, application: application} do
    {:ok, access_token} = OauthAccessTokens.create_token(user, %{application: application})
    assert access_token.resource_owner_id == user.id
    assert access_token.application_id == application.id
  end

  test "create_token/2 with application", %{application: application} do
    {:ok, access_token} = OauthAccessTokens.create_token(application)
    assert is_nil(access_token.resource_owner_id)
    assert access_token.application_id == application.id
  end

  test "create_token/2 adds random token", %{user: user} do
    {:ok, access_token} = OauthAccessTokens.create_token(user)
    {:ok, access_token2} = OauthAccessTokens.create_token(user)
    assert access_token.token != access_token2.token
  end

  test "create_token/2 with custom access token generator", %{user: user} do
    ConfigHelpers.set_config(:access_token_generator, {__MODULE__, :access_token_generator})

    {:ok, access_token} = OauthAccessTokens.create_token(user, %{})
    assert access_token.token == "custom_generated-#{user.id}"
  end

  test "create_token/2 adds previous_refresh_token", %{user: user} do
    {:ok, old_access_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    {:ok, new_access_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true, previous_refresh_token: old_access_token})
    assert new_access_token.previous_refresh_token == old_access_token.refresh_token
  end

  test "create_token/2 adds random refresh token", %{user: user} do
    {:ok, access_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    {:ok, access_token2} = OauthAccessTokens.create_token(user, %{use_refresh_token: true})
    assert access_token.refresh_token != access_token2.refresh_token
  end

  test "create_token/2 doesn't add refresh token when disabled", %{user: user} do
    {:ok, access_token} = OauthAccessTokens.create_token(user, %{use_refresh_token: false})
    assert is_nil(access_token.refresh_token)
  end

  test "create_token/2 with no scopes", %{user: user} do
    assert {:ok, access_token} = OauthAccessTokens.create_token(user)
    assert access_token.scopes == "public"
  end

  test "create_token/2 with custom scopes", %{user: user} do
    assert {:ok, access_token} = OauthAccessTokens.create_token(user, %{scopes: "read"})
    assert access_token.scopes == "read"
  end

  test "create_token/2 with invalid scopes", %{user: user} do
    assert {:error, changeset} = OauthAccessTokens.create_token(user, %{scopes: "invalid"})
    assert changeset.errors[:scopes] == {"not in permitted scopes list: [\"public\", \"read\", \"write\"]", []}
  end

  describe "with application scopes" do
    setup %{user: user, application: application} do
       application = Map.merge(application, %{scopes: "public app:write app:read"})

       %{user: user, application: application}
    end

    test "create_token/2 with no scopes", %{user: user, application: application} do
      assert {:ok, access_token} = OauthAccessTokens.create_token(user, %{application: application})
      assert access_token.scopes == "public"
    end

    test "create_token/2 with custom scopes", %{user: user, application: application} do
      application = Map.merge(application, %{scopes: "app:read"})
      assert {:ok, access_token} = OauthAccessTokens.create_token(user, %{scopes: "app:read", application: application})
      assert access_token.scopes == "app:read"
    end

    test "create_token/2 with invalid scopes", %{user: user, application: application} do
      application = Map.merge(application, %{scopes: "app:read"})
      assert {:error, changeset} = OauthAccessTokens.create_token(user, %{application: application, scopes: "app:write"})
      assert changeset.errors[:scopes] == {"not in permitted scopes list: \"app:read\"", []}
    end
  end

  test "get_or_create_token/2 gets existing token", %{user: user} do
    {:ok, access_token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert is_nil(access_token.application_id)
    assert access_token.resource_owner_id == user.id

    {:ok, access_token2} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert access_token.id == access_token2.id

    update(access_token, scopes: "write read")
    {:ok, access_token3} = OauthAccessTokens.get_or_create_token(user, nil, "read write", %{})
    assert access_token.id == access_token3.id
  end

  test "get_or_create_token/2 with resource owner and application", %{user: user, application: application} do
    {:ok, access_token} = OauthAccessTokens.get_or_create_token(user, application, nil, %{})
    assert access_token.application_id == application.id
    assert access_token.resource_owner_id == user.id

    {:ok, access_token2} = OauthAccessTokens.get_or_create_token(user, application, nil, %{})
    assert access_token2.id == access_token.id

    update(access_token, scopes: "read write")
    {:ok, access_token3} = OauthAccessTokens.get_or_create_token(user, application, "read write", %{})
    assert access_token3.id == access_token.id
  end

  test "get_or_create_token/2 with application", %{application: application} do
    {:ok, access_token} = OauthAccessTokens.get_or_create_token(application, nil, %{})
    assert access_token.application_id == application.id
    assert is_nil(access_token.resource_owner_id)

    {:ok, access_token2} = OauthAccessTokens.get_or_create_token(application, nil, %{})
    assert access_token2.id == access_token.id
  end

  test "get_or_create_token/2 creates token when matching is revoked", %{user: user} do
    {:ok, access_token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    OauthAccessTokens.revoke(access_token)
    {:ok, access_token2} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert access_token2.id != access_token.id
  end

  test "get_or_create_token/2 creates token when matching has expired", %{user: user} do
    {:ok, access_token1} = OauthAccessTokens.create_token(user, %{expires_in: 1})
    {:ok, access_token2} = OauthAccessTokens.create_token(user, %{expires_in: 1})

    {:ok, access_token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert access_token.id == access_token2.id

    inserted_at = NaiveDateTime.add(NaiveDateTime.utc_now(), -access_token.expires_in, :second)
    update(access_token2, inserted_at: inserted_at)

    {:ok, access_token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    assert access_token.id == access_token1.id

    update(access_token1, inserted_at: inserted_at)

    {:ok, access_token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})
    refute access_token.id in [access_token1.id, access_token2.id]
  end

  test "get_or_create_token/2 creates token when params are different", %{user: user} do
    {:ok, access_token} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{})

    {:ok, access_token2} = OauthAccessTokens.get_or_create_token(Fixtures.resource_owner(), nil, nil, %{})
    assert access_token2.id != access_token.id

    application_id = (if System.get_env("UUID") == "all", do: "09b58e2b-8fff-4b8d-ba94-18a06dd4fc29", else: 0)
    {:ok, access_token3} = OauthAccessTokens.get_or_create_token(user, application_id, nil, %{})
    assert access_token3.id != access_token.id

    {:ok, access_token4} = OauthAccessTokens.get_or_create_token(user, nil, nil, %{expires_in: 0})
    assert access_token4.id != access_token.id

    {:ok, access_token5} = OauthAccessTokens.get_or_create_token(user, nil, "read", %{})
    assert access_token5.id != access_token.id
  end

  test "revoke/1 revokes token", %{user: user} do
    {:ok, access_token} = OauthAccessTokens.create_token(user)

    assert {:ok, access_token} = OauthAccessTokens.revoke(access_token)
    assert OauthAccessTokens.is_revoked?(access_token) == true
  end

  test "revoke/1 doesn't revoke revoked tokens", %{user: user} do
    {:ok, access_token} = OauthAccessTokens.create_token(user)
    access_token = Map.merge(access_token, %{revoked_at: NaiveDateTime.utc_now |> NaiveDateTime.add(-86_400, :second)})

    {:ok, access_token2} = OauthAccessTokens.revoke(access_token)
    assert access_token2.revoked_at == access_token.revoked_at
  end

  test "is_revoked?/1#true" do
    assert OauthAccessTokens.is_revoked?(%OauthAccessToken{revoked_at: NaiveDateTime.utc_now})
  end

  test "is_revoked?/1#false" do
    refute OauthAccessTokens.is_revoked?(%OauthAccessToken{revoked_at: nil})
  end

  test "is_accessible?/1#true" do
    access_token = %OauthAccessToken{expires_in: 1, revoked_at: nil, inserted_at: NaiveDateTime.utc_now}
    assert OauthAccessTokens.is_accessible?(access_token)
  end

  test "is_accessible?/1#false when revoked" do
    access_token = %OauthAccessToken{expires_in: 1, revoked_at: NaiveDateTime.utc_now, inserted_at: NaiveDateTime.utc_now}
    refute OauthAccessTokens.is_accessible?(access_token)
  end

  test "is_accessible?/1#false when expired" do
    access_token = %OauthAccessToken{expires_in: 0, revoked_at: nil, inserted_at: NaiveDateTime.utc_now}
    refute OauthAccessTokens.is_accessible?(access_token)

    inserted_at = NaiveDateTime.utc_now |> NaiveDateTime.add(-2, :second)
    access_token = %OauthAccessToken{expires_in: 1, revoked_at: nil, inserted_at: inserted_at}
    refute OauthAccessTokens.is_accessible?(access_token)
  end

  test "is_accessible?/1#false when never expires" do
    access_token = %OauthAccessToken{expires_in: nil, revoked_at: nil, inserted_at: NaiveDateTime.utc_now}
    assert OauthAccessTokens.is_accessible?(access_token)
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
