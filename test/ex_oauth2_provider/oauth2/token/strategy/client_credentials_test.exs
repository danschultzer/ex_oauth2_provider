defmodule ExOauth2Provider.Token.Strategy.ClientCredentialsTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}
  alias ExOauth2Provider.{Config, Token, OauthAccessTokens.OauthAccessToken}

  @client_id            "Jf5rM8hQBc"
  @client_secret        "secret"
  @valid_request        %{"client_id" => @client_id,
                          "client_secret" => @client_secret,
                          "grant_type" => "client_credentials",
                          "scope" => "app:read"}
  @invalid_client_error %{error: :invalid_client,
                          error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
                        }

  setup do
    application = Fixtures.application(Fixtures.resource_owner(), %{uid: @client_id, secret: @client_secret, scopes: "app:read app:write"})
    {:ok, %{application: application}}
  end

  test "#grant/1 error when invalid client" do
    request_invalid_client = Map.merge(@valid_request, %{"client_id" => "invalid"})

    assert Token.grant(request_invalid_client) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/1 error when invalid secret" do
    request_invalid_client = Map.merge(@valid_request, %{"client_secret" => "invalid"})

    assert Token.grant(request_invalid_client) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/1 returns access token", %{application: application} do
    assert {:ok, body} = Token.grant(@valid_request)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert is_nil(access_token.resource_owner_id)
    assert access_token.application_id == application.id
    assert access_token.scopes == "app:read"
    assert access_token.expires_in == Config.access_token_expires_in()

    # MUST NOT have refresh token
    assert access_token.refresh_token == nil
  end
end
