defmodule ExOauth2Provider.Token.Strategy.PasswordTest do
  use ExOauth2Provider.TestCase

  import ExOauth2Provider.Token
  import ExOauth2Provider.Test.Fixture
  import ExOauth2Provider.Test.QueryHelper

  alias ExOauth2Provider.Token.Password

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
    user = fixture(:user, %{email: @username})
    application = fixture(:application, fixture(:user), %{uid: @client_id, secret: @client_secret, scopes: "app:read app:write"})
    {:ok, %{user: user, application: application}}
  end

  test "#grant/1 error when invalid client" do
    request_invalid_client = Map.merge(@valid_request, %{"client_id" => "invalid"})
    assert {:error, error, :unprocessable_entity} = grant(request_invalid_client)
    assert error == @invalid_client_error
  end

  test "#grant/1 error when invalid secret" do
    request_invalid_client = Map.merge(@valid_request, %{"client_secret" => "invalid"})
    assert {:error, error, :unprocessable_entity} = grant(request_invalid_client)
    assert error == @invalid_client_error
  end

  test "#grant/1 error when missing required values" do
    Enum.each(["username", "password"], fn(k) ->
      assert {:error, error, :bad_request} = grant(Map.delete(@valid_request, k))
      assert error == @invalid_request_error
    end)
  end

  test "#grant/1 error when invalid password" do
    assert {:error, :unauthorized, :unauthorized} == grant(Map.merge(@valid_request, %{"password" => "invalid"}))
  end

  test "#grant/1 error when invalid scope" do
    assert {:error, error, :unprocessable_entity} = grant(Map.merge(@valid_request, %{"scope" => "invalid"}))
    assert error == @invalid_scope
  end

  test "#grant/1 error when no password auth set" do
    assert {:error, error, :unprocessable_entity} = Password.grant(@valid_request, %{password_auth: nil, use_refresh_token?: true})
    assert error == %{error: :unsupported_grant_type,
                      error_description: "The authorization grant type is not supported by the authorization server."
                    }
  end

  test "#grant/1 returns access token", %{user: user, application: application} do
    assert {:ok, access_token} = grant(@valid_request)
    assert access_token.access_token == get_last_access_token().token
    assert get_last_access_token().resource_owner_id == user.id
    assert get_last_access_token().application_id == application.id
    assert get_last_access_token().scopes == application.scopes
    assert get_last_access_token().expires_in == ExOauth2Provider.Config.access_token_expires_in
    refute is_nil(get_last_access_token().refresh_token)
  end

  test "#grant/1 doesn't set refresh_token when ExOauth2Provider.Config.use_refresh_token? == false" do
    assert {:ok, access_token} = Password.grant(@valid_request, %{password_auth: ExOauth2Provider.Config.password_auth, use_refresh_token?: false})
    assert access_token.access_token == get_last_access_token().token
    assert is_nil(get_last_access_token().refresh_token)
  end

  test "#grant/1 returns access token with limited scope" do
    assert {:ok, _} = grant(Map.merge(@valid_request, %{"scope" => "app:read"}))
    assert get_last_access_token().scopes == "app:read"
  end
end
