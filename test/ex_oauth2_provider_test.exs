defmodule ExOauth2ProviderTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  alias ExOauth2Provider.Test.{ConfigHelpers, Fixtures, QueryHelpers}
  alias ExOauth2Provider.{OauthAccessTokens, OauthAccessTokens.OauthAccessToken}

  test "authenticate_token/1 error when invalid" do
    assert ExOauth2Provider.authenticate_token(nil) == {:error, :token_inaccessible}
    assert ExOauth2Provider.authenticate_token("secret") == {:error, :token_not_found}
  end

  test "authenticate_token/1 authenticates" do
    access_token = Fixtures.access_token(Fixtures.resource_owner())
    assert ExOauth2Provider.authenticate_token(access_token.token) == {:ok, access_token}
    assert access_token.resource_owner
  end

  test "authenticate_token/1 authenticates with application-wide token" do
    application = Fixtures.application(Fixtures.resource_owner())
    access_token = Fixtures.access_token(application)

    assert {:ok, access_token} = ExOauth2Provider.authenticate_token(access_token.token)
    refute access_token.resource_owner
  end

  test "authenticate_token/1 revokes previous refresh token" do
    user = Fixtures.resource_owner()
    access_token  = Fixtures.access_token(user, %{use_refresh_token: true})
    access_token2 = Fixtures.access_token(user, %{use_refresh_token: true, previous_refresh_token: access_token})

    assert {:ok, access_token} = ExOauth2Provider.authenticate_token(access_token.token)
    access_token = QueryHelpers.get_by(OauthAccessToken, token: access_token.token)
    refute OauthAccessTokens.is_revoked?(access_token)
    access_token2 = QueryHelpers.get_by(OauthAccessToken, token: access_token2.token)
    refute "" == access_token2.previous_refresh_token

    assert {:ok, access_token2} = ExOauth2Provider.authenticate_token(access_token2.token)
    access_token = QueryHelpers.get_by(OauthAccessToken, token: access_token.token)
    assert OauthAccessTokens.is_revoked?(access_token)
    access_token2 = QueryHelpers.get_by(OauthAccessToken, token: access_token2.token)
    assert "" == access_token2.previous_refresh_token
  end

  test "authenticate_token/1 doesn't revoke when refresh_token_revoked_on_use? == false" do
    ConfigHelpers.set_config(:revoke_refresh_token_on_use, false)

    user = Fixtures.resource_owner()
    access_token  = Fixtures.access_token(user, %{use_refresh_token: true})
    access_token2 = Fixtures.access_token(user, %{use_refresh_token: true, previous_refresh_token: access_token})

    assert {:ok, access_token2} = ExOauth2Provider.authenticate_token(access_token2.token)
    access_token = QueryHelpers.get_by(OauthAccessToken, token: access_token.token)
    refute OauthAccessTokens.is_revoked?(access_token)
    access_token2 = QueryHelpers.get_by(OauthAccessToken, token: access_token2.token)
    refute "" == access_token2.previous_refresh_token
  end

  test "authenticate_token/1 error when expired token" do
    access_token = Fixtures.access_token(Fixtures.resource_owner(), %{expires_in: -1})

    assert ExOauth2Provider.authenticate_token(access_token.token) == {:error, :token_inaccessible}
  end

  test "authenticate_token/1 error when revoked token" do
    access_token = Fixtures.access_token(Fixtures.resource_owner(), %{})
    OauthAccessTokens.revoke(access_token)

    assert ExOauth2Provider.authenticate_token(access_token.token) == {:error, :token_inaccessible}
  end

  test "authenticate_token/1 error when invalid resource owner" do
    resource_owner_id = (if is_nil(System.get_env("UUID")), do: 0, else: "09b58e2b-8fff-4b8d-ba94-18a06dd4fc29")
    user = %{Fixtures.resource_owner() | id: resource_owner_id}
    access_token = Fixtures.access_token(user)

    assert ExOauth2Provider.authenticate_token(access_token.token) == {:error, :no_association_found}
  end
end
