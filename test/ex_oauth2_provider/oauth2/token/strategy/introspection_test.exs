defmodule ExOauth2Provider.Token.Strategy.IntrospectionTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.{AccessTokens, Token, Schema}
  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}

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

    expired_token =
      Fixtures.access_token(
        resource_owner: user,
        application: application,
        use_refresh_token: true,
        scopes: "app:read",
        expires_in: -1000
      )

    revoked_token =
      Fixtures.access_token(
        resource_owner: user,
        application: application,
        use_refresh_token: true,
        scopes: "app:read"
      )
    revoked_token = AccessTokens.revoke!(revoked_token, otp_app: :ex_oauth2_provider)

    valid_request = %{
      "client_id" => @client_id,
      "client_secret" => @client_secret,
      "token" => access_token.token
    }

    {:ok,
     %{
       access_token: access_token,
       expired_token: expired_token,
       revoked_token: revoked_token,
       valid_request: valid_request,
       user: user
     }}
  end

  test "#introspect/2 error when invalid client", %{valid_request: valid_request} do
    params = Map.merge(valid_request, %{"client_id" => "invalid"})

    assert Token.introspect(params, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#introspect/2 error when invalid secret", %{valid_request: valid_request} do
    params = Map.merge(valid_request, %{"client_secret" => "invalid"})

    assert Token.introspect(params, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_client_error, :unprocessable_entity}
  end

  test "#introspect/2 non-existing token", %{valid_request: valid_request} do
    params = Map.merge(valid_request, %{"token" => "invalid"})

    assert Token.introspect(params, otp_app: :ex_oauth2_provider) == {:ok, %{active: false}}
  end

  test "#introspect/2 access token", %{
    valid_request: valid_request,
    access_token: access_token,
    user: user
  } do
    created_at = Schema.unix_time_for(access_token.inserted_at)
    expected_introspection =
      {:ok,
       %{
         active: true,
         client_id: @client_id,
         exp: created_at + access_token.expires_in,
         iat: created_at,
         scope: access_token.scopes,
         sub: user.id,
         token_type: "bearer"
       }}

    assert Token.introspect(valid_request, otp_app: :ex_oauth2_provider) == expected_introspection
  end

  test "#introspect/2 access token owned by another application", %{
    valid_request: valid_request,
    access_token: access_token
  } do
    new_application = Fixtures.application(uid: "new_app", client_secret: "new")
    QueryHelpers.change!(access_token, application_id: new_application.id)

    assert Token.introspect(valid_request, otp_app: :ex_oauth2_provider) == {:ok, %{active: false}}
  end

  test "#introspect/2 refresh token", %{
    valid_request: valid_request,
    access_token: access_token
  } do
    params = Map.merge(valid_request, %{"token" => access_token.refresh_token})

    created_at = Schema.unix_time_for(access_token.inserted_at)
    expected_introspection =
      {:ok,
       %{
         active: true,
         client_id: @client_id,
         exp: nil,
         iat: created_at,
         scope: access_token.scopes,
         sub: user.id,
         token_type: "bearer"
       }}

    assert Token.introspect(params, otp_app: :ex_oauth2_provider) == expected_introspection
  end

  test "#introspect/2 expired access token", %{
    valid_request: valid_request,
    expired_token: expired_token
  } do
    params = Map.merge(valid_request, %{"token" => expired_token.token})

    assert Token.introspect(params, otp_app: :ex_oauth2_provider) == {:ok, %{active: false}}
  end

  test "#introspect/2 expired refresh token", %{
    valid_request: valid_request,
    expired_token: expired_token
  } do
    params = Map.merge(valid_request, %{"token" => expired_token.refresh_token})
    {status, introspection} = Token.introspect(params, otp_app: :ex_oauth2_provider)

    assert status == :ok
    assert introspection.active
  end

  test "#introspect/2 revoked access token", %{
    valid_request: valid_request,
    revoked_token: revoked_token,
    user: user
  } do
    params = Map.merge(valid_request, %{"token" => revoked_token.token})

    assert Token.introspect(params, otp_app: :ex_oauth2_provider) == {:ok, %{active: false}}
  end

  test "#introspect/2 revoked refresh token", %{
    valid_request: valid_request,
    revoked_token: revoked_token
  } do
    params = Map.merge(valid_request, %{"token" => revoked_token.refresh_token})

    assert Token.introspect(params, otp_app: :ex_oauth2_provider) == {:ok, %{active: false}}
  end
end
