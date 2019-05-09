defmodule ExOauth2ProviderTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  alias ExOauth2Provider.AccessTokens
  alias ExOauth2Provider.Test.Fixtures
  alias Dummy.{OauthAccessTokens.OauthAccessToken, Repo}

  describe "authenticate_token/2" do
    test "error when invalid" do
      assert ExOauth2Provider.authenticate_token(nil, otp_app: :ex_oauth2_provider) == {:error, :token_inaccessible}
      assert ExOauth2Provider.authenticate_token("secret", otp_app: :ex_oauth2_provider) == {:error, :token_not_found}
    end

    test "authenticates" do
      access_token = Fixtures.access_token()
      assert ExOauth2Provider.authenticate_token(access_token.token, otp_app: :ex_oauth2_provider) == {:ok, access_token}
      assert access_token.resource_owner
    end

    test "authenticates with application-wide token" do
      application = Fixtures.application()
      access_token = Fixtures.application_access_token(application: application)

      assert {:ok, access_token} = ExOauth2Provider.authenticate_token(access_token.token, otp_app: :ex_oauth2_provider)
      refute access_token.resource_owner
    end

    test "revokes previous refresh token" do
      user = Fixtures.resource_owner()
      access_token  = Fixtures.access_token(resource_owner: user, use_refresh_token: true)
      access_token2 = Fixtures.access_token(resource_owner: user, use_refresh_token: true, previous_refresh_token: access_token)

      assert {:ok, access_token} = ExOauth2Provider.authenticate_token(access_token.token, otp_app: :ex_oauth2_provider)
      access_token = Repo.get_by(OauthAccessToken, token: access_token.token)
      refute AccessTokens.is_revoked?(access_token)
      access_token2 = Repo.get_by(OauthAccessToken, token: access_token2.token)
      refute "" == access_token2.previous_refresh_token

      assert {:ok, access_token2} = ExOauth2Provider.authenticate_token(access_token2.token, otp_app: :ex_oauth2_provider)
      access_token = Repo.get_by(OauthAccessToken, token: access_token.token)
      assert AccessTokens.is_revoked?(access_token)
      access_token2 = Repo.get_by(OauthAccessToken, token: access_token2.token)
      assert "" == access_token2.previous_refresh_token
    end

    test "doesn't revoke when refresh_token_revoked_on_use? == false" do
      user = Fixtures.resource_owner()
      access_token  = Fixtures.access_token(resource_owner: user, use_refresh_token: true)
      access_token2 = Fixtures.access_token(resource_owner: user, use_refresh_token: true, previous_refresh_token: access_token)

      assert {:ok, access_token2} = ExOauth2Provider.authenticate_token(access_token2.token, otp_app: :ex_oauth2_provider, revoke_refresh_token_on_use: false)
      access_token = Repo.get_by(OauthAccessToken, token: access_token.token)
      refute AccessTokens.is_revoked?(access_token)
      access_token2 = Repo.get_by(OauthAccessToken, token: access_token2.token)
      refute "" == access_token2.previous_refresh_token
    end

    test "error when expired token" do
      access_token = Fixtures.access_token(expires_in: -1)

      assert ExOauth2Provider.authenticate_token(access_token.token, otp_app: :ex_oauth2_provider) == {:error, :token_inaccessible}
    end

    test "error when revoked token" do
      access_token = Fixtures.access_token()
      AccessTokens.revoke(access_token)

      assert ExOauth2Provider.authenticate_token(access_token.token, otp_app: :ex_oauth2_provider) == {:error, :token_inaccessible}
    end
  end
end
