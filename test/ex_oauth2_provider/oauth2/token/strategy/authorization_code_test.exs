defmodule ExOauth2Provider.Token.Strategy.AuthorizationCodeTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.{ConfigHelpers, Fixtures, QueryHelpers}
  alias ExOauth2Provider.{Config, Token, Token.AuthorizationCode, OauthAccessGrants, OauthAccessTokens.OauthAccessToken}

  @client_id          "Jf5rM8hQBc"
  @client_secret      "secret"
  @code               "code"
  @redirect_uri       "urn:ietf:wg:oauth:2.0:oob"
  @valid_request      %{"client_id" => @client_id,
                        "client_secret" => @client_secret,
                        "code" => @code,
                        "grant_type" => "authorization_code",
                        "redirect_uri" => @redirect_uri}

  @invalid_client_error %{error: :invalid_client,
                          error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
                        }
  @invalid_grant        %{error: :invalid_grant,
                          error_description: "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
                        }

  setup do
    resource_owner = Fixtures.resource_owner()
    application = Fixtures.application(Fixtures.resource_owner(), %{uid: @client_id, secret: @client_secret})
    {:ok, %{resource_owner: resource_owner, application: application}}
  end

  setup %{resource_owner: resource_owner, application: application} do
    access_grant = Fixtures.access_grant(application, resource_owner, @code, @redirect_uri)
    {:ok, %{resource_owner: resource_owner, application: application, access_grant: access_grant}}
  end

  test "#grant/1 returns access token", %{resource_owner: resource_owner, application: application, access_grant: access_grant} do
    assert {:ok, body} = Token.grant(@valid_request)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert access_token.resource_owner_id == resource_owner.id
    assert access_token.application_id == application.id
    assert access_token.scopes == access_grant.scopes
    assert access_token.expires_in == Config.access_token_expires_in()
    refute is_nil(access_token.refresh_token)
  end

  test "#grant/1 returns access token when client secret not required", %{resource_owner: resource_owner, application: application} do
    QueryHelpers.change!(application, secret: "")
    valid_request_no_client_secret = Map.drop(@valid_request, ["client_secret"])

    assert {:ok, body} = Token.grant(valid_request_no_client_secret)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert access_token.resource_owner_id == resource_owner.id
    assert access_token.application_id == application.id
  end

  test "#grant/1 returns access token with custom response handler" do
    ConfigHelpers.set_config(:access_token_response_body_handler, {__MODULE__, :access_token_response_body_handler})

    assert {:ok, body} = AuthorizationCode.grant(@valid_request)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.custom_attr == access_token.inserted_at
  end

  test "#grant/1 doesn't set refresh_token when ExOauth2Provider.Config.use_refresh_token? == false" do
    ConfigHelpers.set_config(:use_refresh_token, false)

    assert {:ok, body} = AuthorizationCode.grant(@valid_request)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert is_nil(access_token.refresh_token)
  end

  test "#grant/1 can't use grant twice" do
    assert {:ok, _body} = Token.grant(@valid_request)
    assert Token.grant(@valid_request) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/1 doesn't duplicate access token", %{resource_owner: resource_owner, application: application} do
    assert {:ok, body} = Token.grant(@valid_request)
    access_grant = Fixtures.access_grant(application, resource_owner, "new_code", @redirect_uri)
    valid_request = Map.merge(@valid_request, %{"code" => access_grant.token})
    assert {:ok, body2} = Token.grant(valid_request)

    assert body.access_token == body2.access_token
  end

  test "#grant/1 error when invalid client" do
    request_invalid_client = Map.merge(@valid_request, %{"client_id" => "invalid"})

    assert Token.grant(request_invalid_client) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/1 error when invalid secret" do
    request_invalid_client = Map.merge(@valid_request, %{"client_secret" => "invalid"})

    assert Token.grant(request_invalid_client) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/1 error when invalid grant" do
    request_invalid_grant = Map.merge(@valid_request, %{"code" => "invalid"})

    assert Token.grant(request_invalid_grant) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/1 error when grant owned by another client", %{access_grant: access_grant} do
    new_application = Fixtures.application(Fixtures.resource_owner(), %{uid: "new_app"})
    QueryHelpers.change!(access_grant, application_id: new_application.id)

    assert Token.grant(@valid_request) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/1 error when revoked grant", %{access_grant: access_grant} do
    QueryHelpers.change!(access_grant, revoked_at: DateTime.utc_now())

    assert Token.grant(@valid_request) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/1 error when grant expired", %{access_grant: access_grant} do
    inserted_at = NaiveDateTime.add(NaiveDateTime.utc_now(), -access_grant.expires_in, :second)
    QueryHelpers.change!(access_grant, inserted_at: inserted_at)

    assert Token.grant(@valid_request) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/1 error when grant revoked", %{access_grant: access_grant} do
    OauthAccessGrants.revoke(access_grant)

    assert Token.grant(@valid_request) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/1 error when invalid redirect_uri" do
    request_invalid_redirect_uri = Map.merge(@valid_request, %{"redirect_uri" => "invalid"})

    assert Token.grant(request_invalid_redirect_uri) == {:error, @invalid_grant, :unprocessable_entity}
  end

  def access_token_response_body_handler(body, access_token) do
    Map.merge(body, %{custom_attr: access_token.inserted_at})
  end
end
