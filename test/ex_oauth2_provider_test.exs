defmodule ExOauth2ProviderTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  alias ExOauth2Provider.Test.{ConfigHelpers, Fixtures, Repo}
  alias ExOauth2Provider.{OauthAccessTokens, OauthAccessTokens.OauthAccessToken}

  describe "authenticate_token/1" do
    test "error when invalid" do
      assert ExOauth2Provider.authenticate_token(nil) == {:error, :token_inaccessible}
      assert ExOauth2Provider.authenticate_token("secret") == {:error, :token_not_found}
    end

    test "authenticates" do
      access_token = Fixtures.access_token()
      assert ExOauth2Provider.authenticate_token(access_token.token) == {:ok, access_token}
      assert access_token.resource_owner
    end

    test "authenticates with application-wide token" do
      application = Fixtures.application()
      access_token = Fixtures.access_token(resource_owner: application)

      assert {:ok, access_token} = ExOauth2Provider.authenticate_token(access_token.token)
      refute access_token.resource_owner
    end

    test "revokes previous refresh token" do
      user = Fixtures.resource_owner()
      access_token  = Fixtures.access_token(resource_owner: user, use_refresh_token: true)
      access_token2 = Fixtures.access_token(resource_owner: user, use_refresh_token: true, previous_refresh_token: access_token)

      assert {:ok, access_token} = ExOauth2Provider.authenticate_token(access_token.token)
      access_token = Repo.get_by(OauthAccessToken, token: access_token.token)
      refute OauthAccessTokens.is_revoked?(access_token)
      access_token2 = Repo.get_by(OauthAccessToken, token: access_token2.token)
      refute "" == access_token2.previous_refresh_token

      assert {:ok, access_token2} = ExOauth2Provider.authenticate_token(access_token2.token)
      access_token = Repo.get_by(OauthAccessToken, token: access_token.token)
      assert OauthAccessTokens.is_revoked?(access_token)
      access_token2 = Repo.get_by(OauthAccessToken, token: access_token2.token)
      assert "" == access_token2.previous_refresh_token
    end

    test "doesn't revoke when refresh_token_revoked_on_use? == false" do
      ConfigHelpers.set_config(:revoke_refresh_token_on_use, false)

      user = Fixtures.resource_owner()
      access_token  = Fixtures.access_token(resource_owner: user, use_refresh_token: true)
      access_token2 = Fixtures.access_token(resource_owner: user, use_refresh_token: true, previous_refresh_token: access_token)

      assert {:ok, access_token2} = ExOauth2Provider.authenticate_token(access_token2.token)
      access_token = Repo.get_by(OauthAccessToken, token: access_token.token)
      refute OauthAccessTokens.is_revoked?(access_token)
      access_token2 = Repo.get_by(OauthAccessToken, token: access_token2.token)
      refute "" == access_token2.previous_refresh_token
    end

    test "error when expired token" do
      access_token = Fixtures.access_token(expires_in: -1)

      assert ExOauth2Provider.authenticate_token(access_token.token) == {:error, :token_inaccessible}
    end

    test "error when revoked token" do
      access_token = Fixtures.access_token()
      OauthAccessTokens.revoke(access_token)

      assert ExOauth2Provider.authenticate_token(access_token.token) == {:error, :token_inaccessible}
    end

    test "error when invalid resource owner" do
      resource_owner_id = (if is_nil(System.get_env("UUID")), do: 0, else: "09b58e2b-8fff-4b8d-ba94-18a06dd4fc29")
      user = %{Fixtures.resource_owner() | id: resource_owner_id}
      access_token = Fixtures.access_token(resource_owner: user)

      assert ExOauth2Provider.authenticate_token(access_token.token) == {:error, :no_association_found}
    end
  end
end
