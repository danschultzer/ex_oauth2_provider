defmodule ExOauth2Provider.Token.Strategy.RevokeTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.{AccessTokens, Token}
  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}
  alias Dummy.OauthAccessTokens.OauthAccessToken

  @client_id "Jf5rM8hQBc"
  @client_secret "secret"
  @invalid_client_error %{
    error: :invalid_client,
    error_description:
      "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
  }

  setup do
    user = Fixtures.resource_owner()

    application =
      Fixtures.application(
        resource_owner: user,
        uid: @client_id,
        secret: @client_secret,
        scopes: "app:read app:write"
      )

    access_token =
      Fixtures.access_token(
        resource_owner: user,
        application: application,
        use_refresh_token: true,
        scopes: "app:read"
      )

    valid_request = %{
      "client_id" => @client_id,
      "client_secret" => @client_secret,
      "token" => access_token.token
    }

    {:ok, %{access_token: access_token, valid_request: valid_request}}
  end

  test "#revoke/2 error when invalid client", %{valid_request: valid_request} do
    params = Map.merge(valid_request, %{"client_id" => "invalid"})

    assert Token.revoke(params, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#revoke/2 error when invalid secret", %{valid_request: valid_request} do
    params = Map.merge(valid_request, %{"client_secret" => "invalid"})

    assert Token.revoke(params, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#revoke/2 when missing token", %{valid_request: valid_request} do
    params = Map.delete(valid_request, "token")

    assert Token.revoke(params, otp_app: :ex_oauth2_provider) == {:ok, %{}}
    refute AccessTokens.is_revoked?(QueryHelpers.get_latest_inserted(OauthAccessToken))
  end

  test "#revoke/2 when invalid token", %{valid_request: valid_request} do
    params = Map.merge(valid_request, %{"token" => "invalid"})

    assert Token.revoke(params, otp_app: :ex_oauth2_provider) == {:ok, %{}}
    refute AccessTokens.is_revoked?(QueryHelpers.get_latest_inserted(OauthAccessToken))
  end

  test "#revoke/2 when access token owned by another client", %{
    valid_request: valid_request,
    access_token: access_token
  } do
    new_application = Fixtures.application(uid: "new_app", secret: "new")
    QueryHelpers.change!(access_token, application_id: new_application.id)

    assert Token.revoke(valid_request, otp_app: :ex_oauth2_provider) == {:ok, %{}}
    refute AccessTokens.is_revoked?(QueryHelpers.get_latest_inserted(OauthAccessToken))
  end

  test "#revoke/2 when access token not owned by a client", %{access_token: access_token} do
    QueryHelpers.change!(access_token, application_id: nil)

    params = %{"token" => access_token.token}

    assert Token.revoke(params, otp_app: :ex_oauth2_provider) == {:ok, %{}}
    assert AccessTokens.is_revoked?(QueryHelpers.get_latest_inserted(OauthAccessToken))
  end

  test "#revoke/2", %{valid_request: valid_request} do
    assert Token.revoke(valid_request, otp_app: :ex_oauth2_provider) == {:ok, %{}}
    assert AccessTokens.is_revoked?(QueryHelpers.get_latest_inserted(OauthAccessToken))
  end
end
