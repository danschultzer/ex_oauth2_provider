defmodule ExOauth2Provider.Token.Strategy.RefreshTokenTest do
  use ExOauth2Provider.TestCase

  import ExOauth2Provider.Token
  import ExOauth2Provider.Test.Fixture

  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.Token.RefreshToken

  @client_id            "Jf5rM8hQBc"
  @client_secret        "secret"
  @invalid_client_error  %{error: :invalid_client,
                           error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
                         }
  @invalid_request_error %{error: :invalid_request,
                           error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
                         }

  setup do
    user = fixture(:user)
    application = fixture(:application, user, %{uid: @client_id, secret: @client_secret, scopes: "app:read app:write"})
    access_token = fixture(:access_token, user, %{application: application, use_refresh_token: true})

    valid_request = %{"client_id" => @client_id,
                      "client_secret" => @client_secret,
                      "grant_type" => "refresh_token",
                      "refresh_token" => access_token.refresh_token}
    {:ok, %{access_token: access_token, valid_request: valid_request}}
  end

  test "#grant/1 error when invalid client", %{valid_request: valid_request} do
    request_invalid_client = Map.merge(valid_request, %{"client_id" => "invalid"})
    assert {:error, error, :unprocessable_entity} = grant(request_invalid_client)
    assert error == @invalid_client_error
  end

  test "#grant/1 error when invalid secret", %{valid_request: valid_request} do
    request_invalid_client = Map.merge(valid_request, %{"client_secret" => "invalid"})
    assert {:error, error, :unprocessable_entity} = grant(request_invalid_client)
    assert error == @invalid_client_error
  end

  test "#grant/1 error when missing token", %{valid_request: valid_request} do
    assert {:error, error, :bad_request} = grant(Map.delete(valid_request, "refresh_token"))
    assert error == @invalid_request_error
  end

  test "#grant/1 error when invalid token", %{valid_request: valid_request} do
    assert {:error, error, :bad_request} = grant(Map.merge(valid_request, %{"refresh_token" => "invalid"}))
    assert error == @invalid_request_error
  end

  test "#grant/1 error when access token owned by another client", %{valid_request: valid_request, access_token: access_token} do
    new_application = fixture(:application, fixture(:user), %{uid: "new_app"})
    changeset = Ecto.Changeset.change access_token, application_id: new_application.id
    ExOauth2Provider.repo.update! changeset

    assert {:error, error, :bad_request} = grant(valid_request)
    assert error == @invalid_request_error
  end

  test "#grant/1 returns access token", %{valid_request: valid_request, access_token: access_token} do
    assert {:ok, new_access_token} = grant(valid_request)

    access_token = ExOauth2Provider.repo.get_by(OauthAccessTokens.OauthAccessToken, id: access_token.id)
    new_access_token = ExOauth2Provider.repo.get_by(OauthAccessTokens.OauthAccessToken, token: new_access_token.access_token)

    refute access_token.token == new_access_token.token
    assert access_token.resource_owner_id == new_access_token.resource_owner_id
    assert access_token.application_id == new_access_token.application_id
    assert access_token.scopes == new_access_token.scopes
    assert ExOauth2Provider.Config.access_token_expires_in == new_access_token.expires_in
    assert access_token.refresh_token == new_access_token.previous_refresh_token
    assert OauthAccessTokens.is_revoked?(access_token)
  end

  def access_token_response_body_handler(body, access_token) do
    body
    |> Map.merge(%{custom_attr: access_token.inserted_at})
  end

  test "#grant/1 returns access token with custom response handler", %{valid_request: valid_request} do
    assert {:ok, body} = RefreshToken.grant(valid_request, %{refresh_token_revoked_on_use?: false, access_token_response_body_handler: {ExOauth2Provider.Token.Strategy.AuthorizationCodeTest, :access_token_response_body_handler}})
    access_token = ExOauth2Provider.repo.get_by(OauthAccessTokens.OauthAccessToken, token: body.access_token)
    assert access_token.inserted_at == body.custom_attr
  end

  test "#grant/1 when refresh_token_revoked_on_use? == false", %{valid_request: valid_request, access_token: access_token} do
    assert {:ok, new_access_token} = RefreshToken.grant(valid_request, %{refresh_token_revoked_on_use?: false, access_token_response_body_handler: nil})

    access_token = ExOauth2Provider.repo.get_by(OauthAccessTokens.OauthAccessToken, id: access_token.id)
    new_access_token = ExOauth2Provider.repo.get_by(OauthAccessTokens.OauthAccessToken, token: new_access_token.access_token)

    assert "" == new_access_token.previous_refresh_token
    refute OauthAccessTokens.is_revoked?(access_token)
  end
end
