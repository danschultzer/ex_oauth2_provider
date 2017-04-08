defmodule ExOauth2Provider.AuthorizationTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Authorization

  import ExOauth2Provider.Factory

  @client_id              "Jf5rM8hQBc"
  @client_secret          "secret"
  @valid_request          %{"client_id" => @client_id, "response_type" => "code", "scope" => "app:read app:write"}
  @invalid_request        %{error: :invalid_request,
                            error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
                          }
  @invalid_response_type  %{error: :unsupported_response_type,
                            error_description: "The authorization server does not support this response type."
                          }

  setup do
    user = insert(:user)
    insert(:application, %{uid: @client_id, secret: @client_secret, resource_owner_id: user.id})
    {:ok, %{resource_owner: user}}
  end

  test "#preauthorize/2 error when missing response_type", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = preauthorize(resource_owner, Map.delete(@valid_request, "response_type"))
    assert error == @invalid_request
  end

  test "#preauthorize/2 rejects when unsupported response type", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} = preauthorize(resource_owner, Map.merge(@valid_request, %{"response_type" => "invalid"}))
    assert error == @invalid_response_type
  end

  test "#authorize/2 error when missing response_type", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = authorize(resource_owner, Map.delete(@valid_request, "response_type"))
    assert error == @invalid_request
  end

  test "#authorize/2 rejects when unsupported response type", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} = authorize(resource_owner, Map.merge(@valid_request, %{"response_type" => "invalid"}))
    assert error == @invalid_response_type
  end


  test "#deny/2 error when missing response_type", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = deny(resource_owner, Map.delete(@valid_request, "response_type"))
    assert error == @invalid_request
  end

  test "#deny/2 rejects when unsupported response type", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} = deny(resource_owner, Map.merge(@valid_request, %{"response_type" => "invalid"}))
    assert error == @invalid_response_type
  end
end
