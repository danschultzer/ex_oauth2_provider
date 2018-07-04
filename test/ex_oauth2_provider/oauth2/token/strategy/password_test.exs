defmodule ExOauth2Provider.Token.Strategy.PasswordTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.{ConfigHelpers, Fixtures, QueryHelpers}
  alias ExOauth2Provider.{Config, Token, Token.Password, OauthAccessTokens.OauthAccessToken}

  @client_id            "Jf5rM8hQBc"
  @client_secret        "secret"
  @username             "testuser@example.com"
  @password             "secret"
  @valid_request        %{"client_id" => @client_id,
                          "client_secret" => @client_secret,
                          "grant_type" => "password",
                          "username" => @username,
                          "password" => @password}
  @invalid_client_error  %{error: :invalid_client,
                           error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
                         }
  @invalid_request_error %{error: :invalid_request,
                           error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
                         }
  @invalid_scope         %{error: :invalid_scope,
                           error_description: "The requested scope is invalid, unknown, or malformed."
                         }

  setup do
    user = Fixtures.resource_owner(%{email: @username})
    application = Fixtures.application(Fixtures.resource_owner(), %{uid: @client_id, secret: @client_secret, scopes: "app:read app:write"})
    {:ok, %{user: user, application: application}}
  end

  test "#grant/1 error when invalid client" do
    request_invalid_client = Map.merge(@valid_request, %{"client_id" => "invalid"})

    assert Token.grant(request_invalid_client) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/1 error when invalid secret" do
    request_invalid_client = Map.merge(@valid_request, %{"client_secret" => "invalid"})
    assert Token.grant(request_invalid_client) == {:error, @invalid_client_error, :unprocessable_entity}

    request_invalid_client = Map.delete(@valid_request, "client_secret")
    assert Token.grant(request_invalid_client) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/1 error when missing required values" do
    Enum.each(["username", "password"], fn(k) ->
      params = Map.delete(@valid_request, k)
      assert Token.grant(params) == {:error, @invalid_request_error, :bad_request}
    end)
  end

  test "#grant/1 error when invalid password" do
    params = Map.merge(@valid_request, %{"password" => "invalid"})

    assert Token.grant(params) == {:error, :unauthorized, :unauthorized}
  end

  test "#grant/1 error when invalid scope" do
    params = Map.merge(@valid_request, %{"scope" => "invalid"})

    assert Token.grant(params) == {:error, @invalid_scope, :unprocessable_entity}
  end

  test "#grant/1 error when no password auth set" do
    ConfigHelpers.set_config(:password_auth, nil)
    expected_error = %{error: :unsupported_grant_type, error_description: "The authorization grant type is not supported by the authorization server."}

    assert Password.grant(@valid_request) == {:error, expected_error, :unprocessable_entity}
  end

  test "#grant/1 returns access token", %{user: user, application: application} do
    assert {:ok, body} = Token.grant(@valid_request)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert access_token.resource_owner_id == user.id
    assert access_token.application_id == application.id
    assert access_token.scopes == application.scopes
    assert access_token.expires_in == Config.access_token_expires_in()
    refute is_nil(access_token.refresh_token)
  end

  test "#grant/1 returns access token when only client_id required", %{user: user, application: application} do
    QueryHelpers.change!(application, secret: "")

    params = Map.delete(@valid_request, "client_secret")

    assert {:ok, body} = Token.grant(params)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert access_token.resource_owner_id == user.id
    assert access_token.application_id == application.id
  end

  test "#grant/1 returns access token with custom response handler" do
    ConfigHelpers.set_config(:access_token_response_body_handler, {__MODULE__, :access_token_response_body_handler})
    assert {:ok, body} = Password.grant(@valid_request)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.custom_attr == access_token.inserted_at
  end

  test "#grant/1 doesn't set refresh_token when ExOauth2Provider.Config.use_refresh_token? == false" do
    ConfigHelpers.set_config(:use_refresh_token, false)
    assert {:ok, body} = Password.grant(@valid_request)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert is_nil(access_token.refresh_token)
  end

  test "#grant/1 returns access token with limited scope" do
    params = Map.merge(@valid_request, %{"scope" => "app:read"})
    assert {:ok, _} = Token.grant(params)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert access_token.scopes == "app:read"
  end

  def access_token_response_body_handler(body, access_token) do
    Map.merge(body, %{custom_attr: access_token.inserted_at})
  end
end
