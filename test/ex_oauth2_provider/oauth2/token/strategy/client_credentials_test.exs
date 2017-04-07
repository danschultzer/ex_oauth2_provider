defmodule ExOauth2Provider.Token.Strategy.ClientCredentialsTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Token
  import ExOauth2Provider.Factory
  import Ecto.Query

  @client_id            "Jf5rM8hQBc"
  @client_secret        "secret"
  @valid_request        %{"client_id" => @client_id,
                          "client_secret" => @client_secret,
                          "grant_type" => "client_credentials"}
  @invalid_client_error %{error: :invalid_client,
                          error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
                        }

  def get_last_access_token do
    ExOauth2Provider.repo.one(from x in ExOauth2Provider.OauthAccessTokens.OauthAccessToken,
      order_by: [desc: x.id], limit: 1)
  end

  def fixture(:application) do
    insert(:application, %{uid: @client_id, secret: @client_secret, resource_owner_id: fixture(:resource_owner).id})
  end

  def fixture(:resource_owner) do
    insert(:user)
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

  test "#grant/1 returns access token", %{application: application} do
    assert {:ok, access_token} = grant(@valid_request)
    assert access_token.access_token == get_last_access_token().token
    assert get_last_access_token().resource_owner_id == application.resource_owner_id
    assert get_last_access_token().application_id == application.id
    assert get_last_access_token().scopes == application.scopes
    assert get_last_access_token().expires_in == ExOauth2Provider.access_token_expires_in

    # MUST NOT have refresh token
    assert get_last_access_token().refresh_token == nil
  end
end
