defmodule ExOauth2Provider.Token.Strategy.AuthorizationCodeTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.{Config, Token, Token.AuthorizationCode, AccessGrants}
  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}
  alias Dummy.OauthAccessTokens.OauthAccessToken

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
    application = Fixtures.application(uid: @client_id, secret: @client_secret)
    {:ok, %{resource_owner: resource_owner, application: application}}
  end

  setup %{resource_owner: resource_owner, application: application} do
    access_grant = Fixtures.access_grant(application, resource_owner, @code, @redirect_uri)
    {:ok, %{resource_owner: resource_owner, application: application, access_grant: access_grant}}
  end

  test "#grant/2 returns access token", %{resource_owner: resource_owner, application: application, access_grant: access_grant} do
    assert {:ok, body} = Token.grant(@valid_request, otp_app: :ex_oauth2_provider)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert access_token.resource_owner_id == resource_owner.id
    assert access_token.application_id == application.id
    assert access_token.scopes == access_grant.scopes
    assert access_token.expires_in == Config.access_token_expires_in(otp_app: :ex_oauth2_provider)
    refute is_nil(access_token.refresh_token)
  end

  test "#grant/2 returns access token when client secret not required", %{resource_owner: resource_owner, application: application} do
    QueryHelpers.change!(application, secret: "")
    valid_request_no_client_secret = Map.drop(@valid_request, ["client_secret"])

    assert {:ok, body} = Token.grant(valid_request_no_client_secret, otp_app: :ex_oauth2_provider)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert access_token.resource_owner_id == resource_owner.id
    assert access_token.application_id == application.id
  end

  test "#grant/2 returns access token with custom response handler" do
    assert {:ok, body} = AuthorizationCode.grant(@valid_request, otp_app: :ex_oauth2_provider, access_token_response_body_handler: {__MODULE__, :access_token_response_body_handler})
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.custom_attr == access_token.inserted_at
  end

  test "#grant/2 doesn't set refresh_token when ExOauth2Provider.Config.use_refresh_token? == false" do
    assert {:ok, body} = AuthorizationCode.grant(@valid_request, otp_app: :ex_oauth2_provider, use_refresh_token: false)
    access_token = QueryHelpers.get_latest_inserted(OauthAccessToken)

    assert body.access_token == access_token.token
    assert is_nil(access_token.refresh_token)
  end

  test "#grant/2 can't use grant twice" do
    assert {:ok, _body} = Token.grant(@valid_request, otp_app: :ex_oauth2_provider)
    assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/2 doesn't duplicate access token", %{resource_owner: resource_owner, application: application} do
    assert {:ok, body} = Token.grant(@valid_request, otp_app: :ex_oauth2_provider)
    access_grant = Fixtures.access_grant(application, resource_owner, "new_code", @redirect_uri)
    valid_request = Map.merge(@valid_request, %{"code" => access_grant.token})
    assert {:ok, body2} = Token.grant(valid_request, otp_app: :ex_oauth2_provider)

    assert body.access_token == body2.access_token
  end

  test "#grant/2 error when invalid client" do
    request_invalid_client = Map.merge(@valid_request, %{"client_id" => "invalid"})

    assert Token.grant(request_invalid_client, otp_app: :ex_oauth2_provider) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/2 error when invalid secret" do
    request_invalid_client = Map.merge(@valid_request, %{"client_secret" => "invalid"})

    assert Token.grant(request_invalid_client, otp_app: :ex_oauth2_provider) == {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#grant/2 error when invalid grant" do
    request_invalid_grant = Map.merge(@valid_request, %{"code" => "invalid"})

    assert Token.grant(request_invalid_grant, otp_app: :ex_oauth2_provider) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/2 error when grant owned by another client", %{access_grant: access_grant} do
    new_application = Fixtures.application(uid: "new_app")
    QueryHelpers.change!(access_grant, application_id: new_application.id)

    assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/2 error when revoked grant", %{access_grant: access_grant} do
    QueryHelpers.change!(access_grant, revoked_at: DateTime.utc_now())

    assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/2 error when grant expired", %{access_grant: access_grant} do
    inserted_at = QueryHelpers.timestamp(OauthAccessToken, :inserted_at, seconds: -access_grant.expires_in)
    QueryHelpers.change!(access_grant, inserted_at: inserted_at)

    assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/2 error when grant revoked", %{access_grant: access_grant} do
    AccessGrants.revoke(access_grant, otp_app: :ex_oauth2_provider)

    assert Token.grant(@valid_request, otp_app: :ex_oauth2_provider) == {:error, @invalid_grant, :unprocessable_entity}
  end

  test "#grant/2 error when invalid redirect_uri" do
    request_invalid_redirect_uri = Map.merge(@valid_request, %{"redirect_uri" => "invalid"})

    assert Token.grant(request_invalid_redirect_uri, otp_app: :ex_oauth2_provider) == {:error, @invalid_grant, :unprocessable_entity}
  end

  describe "pkce enabled for grant" do
    @code_plain "code_plain"
    @code_s256 "code_s256"

    @code_challenge "1234567890abcdefrety1234567890abcdefrety.~-_"
    @unmatching_code_challenge "1234567890abcdefrety1234567890abcdefrety.~-1"
    @s256_code_challenge :crypto.hash(:sha256, @code_challenge) |> Base.url_encode64(padding: false)

    @valid_plain_request Map.merge(@valid_request, %{
      "code_verifier" => @code_challenge,
      "code" => @code_plain
    })
    @valid_s256_request Map.merge(@valid_request, %{
      "code_verifier" => @code_challenge,
      "code" => @code_s256
    })

    @invalid_request %{
      error: :invalid_request,
      error_description:
        "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }

    setup %{resource_owner: resource_owner, application: application, access_grant: access_grant} do
      plain_grant = Fixtures.access_grant(
        application, resource_owner, @code_plain, @redirect_uri, code_challenge: @code_challenge, code_challenge_method: "plain"
      )
      s256_grant = Fixtures.access_grant(
        application, resource_owner, @code_s256, @redirect_uri, code_challenge: @s256_code_challenge, code_challenge_method: "S256"
      )

      {:ok, %{
        resource_owner: resource_owner,
        application: application,
        no_pkce_grant: access_grant,
        plain_grant: plain_grant,
        s256_grant: s256_grant
      }}
    end

    test "#grant/2 missing code_verifier" do
      request = Map.merge(@valid_request, %{"code" => @code_plain})
      assert {:error, @invalid_request, :bad_request} == Token.grant(request, otp_app: :ex_oauth2_provider)
    end

    test "#grant/2 plain challenge method with unmatching code verifier" do
      request = Map.merge(@valid_plain_request, %{"code_verifier" => @unmatching_code_challenge})
      assert {:error, @invalid_grant, :unprocessable_entity} == Token.grant(request, otp_app: :ex_oauth2_provider)
    end

    test "#grant/2 S256 challenge method with unmatching code verifier" do
      request = Map.merge(@valid_s256_request, %{"code_verifier" => @unmatching_code_challenge})
      assert {:error, @invalid_grant, :unprocessable_entity} == Token.grant(request, otp_app: :ex_oauth2_provider)
    end

    test "#grant/2 returns access token with plain challenge method" do
      assert {:ok, %{access_token: actual_token}} = Token.grant(@valid_plain_request, otp_app: :ex_oauth2_provider)
      assert %{token: ^actual_token} = QueryHelpers.get_latest_inserted(OauthAccessToken)
    end

    test "#grant/2 returns access token with S256 challenge method" do
      assert {:ok, %{access_token: actual_token}} = Token.grant(@valid_s256_request, otp_app: :ex_oauth2_provider)
      assert %{token: ^actual_token} = QueryHelpers.get_latest_inserted(OauthAccessToken)
    end
  end

  def access_token_response_body_handler(body, access_token) do
    Map.merge(body, %{custom_attr: access_token.inserted_at})
  end
end
