defmodule ExOauth2Provider.Token.Strategy.PasswordTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Token
  import ExOauth2Provider.Factory
  import Ecto.Query

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

  def get_last_access_token do
    ExOauth2Provider.repo.one(from x in ExOauth2Provider.OauthAccessTokens.OauthAccessToken,
      order_by: [desc: x.id], limit: 1)
  end

  def fixture(:application) do
    insert(:application, %{uid: @client_id, secret: @client_secret, resource_owner_id: fixture(:resource_owner).id, scopes: "app:read app:write"})
  end

  def fixture(:resource_owner) do
    insert(:user, email: @username)
  end

  setup do
    application = fixture(:application)
    {:ok, %{application: application}}
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

  test "#grant/1 returns access token", %{application: application} do
    assert {:ok, access_token} = grant(@valid_request)
    assert access_token.access_token == get_last_access_token().token
    assert get_last_access_token().resource_owner_id == application.resource_owner_id
    assert get_last_access_token().application_id == application.id
    assert get_last_access_token().scopes == application.scopes
    assert get_last_access_token().expires_in == ExOauth2Provider.access_token_expires_in
  end

  test "#grant/1 returns access token with limited scope" do
    assert {:ok, _} = grant(Map.merge(@valid_request, %{"scope" => "app:read"}))
    assert get_last_access_token().scopes == "app:read"
  end
end
