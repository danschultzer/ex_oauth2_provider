defmodule ExOauth2Provider.Token.Strategy.RefreshTokenTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.{ConfigHelpers, Fixtures, QueryHelpers}
  alias ExOauth2Provider.{Config, OauthAccessTokens, OauthAccessTokens.OauthAccessToken, Token, Token.RefreshToken}

  @client_id            "Jf5rM8hQBc"
  @client_secret        "secret"
  @invalid_client_error  %{error: :invalid_client,
                           error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
                         }
  @invalid_request_error %{error: :invalid_request,
                           error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
                         }

  setup do
    user = Fixtures.resource_owner()
    application = Fixtures.application(user, %{uid: @client_id, secret: @client_secret, scopes: "app:read app:write"})
    access_token = Fixtures.access_token(user, %{application: application, use_refresh_token: true, scopes: "app:read"})

    valid_request = %{"client_id" => @client_id,
                      "client_secret" => @client_secret,
                      "grant_type" => "refresh_token",
                      "refresh_token" => access_token.refresh_token}
    {:ok, %{access_token: access_token, valid_request: valid_request}}
  end

  test "#grant/1 error when invalid client", %{valid_request: valid_request} do
    request_invalid_client = Map.merge(valid_request, %{"client_id" => "invalid"})

    assert Token.grant(request_invalid_client) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/1 error when invalid secret", %{valid_request: valid_request} do
    request_invalid_client = Map.merge(valid_request, %{"client_secret" => "invalid"})

    assert Token.grant(request_invalid_client) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/1 error when missing token", %{valid_request: valid_request} do
    params = Map.delete(valid_request, "refresh_token")

    assert Token.grant(params) == {:error, @invalid_request_error, :bad_request}
  end

  test "#grant/1 error when invalid token", %{valid_request: valid_request} do
    params = Map.merge(valid_request, %{"refresh_token" => "invalid"})

    assert Token.grant(params) == {:error, @invalid_request_error, :bad_request}
  end

  test "#grant/1 error when access token owned by another client", %{valid_request: valid_request, access_token: access_token} do
    new_application = Fixtures.application(Fixtures.resource_owner(), %{uid: "new_app"})
    QueryHelpers.change!(access_token, application_id: new_application.id)

    assert Token.grant(valid_request) == {:error, @invalid_request_error, :bad_request}
  end

  test "#grant/1 error when access token has been revoked", %{valid_request: valid_request, access_token: access_token} do
    QueryHelpers.change!(access_token, revoked_at: DateTime.utc_now())

    assert Token.grant(valid_request) == {:error, @invalid_request_error, :bad_request}
  end

  test "#grant/1 returns access token", %{valid_request: valid_request, access_token: access_token} do
    assert {:ok, new_access_token} = Token.grant(valid_request)

    access_token = QueryHelpers.get_by(OauthAccessToken, id: access_token.id)
    new_access_token = QueryHelpers.get_by(OauthAccessToken, token: new_access_token.access_token)

    refute new_access_token.token == access_token.token
    assert new_access_token.resource_owner_id == access_token.resource_owner_id
    assert new_access_token.application_id == access_token.application_id
    assert new_access_token.scopes == access_token.scopes
    assert new_access_token.expires_in == Config.access_token_expires_in()
    assert new_access_token.previous_refresh_token == access_token.refresh_token
    assert OauthAccessTokens.is_revoked?(access_token)
  end

  test "#grant/1 returns access token with custom response handler", %{valid_request: valid_request} do
    ConfigHelpers.set_config(:access_token_response_body_handler, {__MODULE__, :access_token_response_body_handler})

    assert {:ok, body} = RefreshToken.grant(valid_request)
    access_token = QueryHelpers.get_by(OauthAccessToken, token: body.access_token)
    assert body.custom_attr == access_token.inserted_at
  end

  test "#grant/1 when refresh_token_revoked_on_use? == false", %{valid_request: valid_request, access_token: access_token} do
    ConfigHelpers.set_config(:revoke_refresh_token_on_use, false)

    assert {:ok, new_access_token} = RefreshToken.grant(valid_request)

    access_token = QueryHelpers.get_by(OauthAccessToken, id: access_token.id)
    new_access_token = QueryHelpers.get_by(OauthAccessToken, token: new_access_token.access_token)

    assert new_access_token.previous_refresh_token == ""
    refute OauthAccessTokens.is_revoked?(access_token)
  end

  def access_token_response_body_handler(body, access_token) do
    Map.merge(body, %{custom_attr: access_token.inserted_at})
  end
end
