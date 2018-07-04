defmodule ExOauth2Provider.AuthorizationTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Test.{Fixtures, QueryHelpers}
  alias ExOauth2Provider.Authorization

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
    user = Fixtures.resource_owner()
    application = Fixtures.application(user, %{uid: @client_id, secret: @client_secret})
    {:ok, %{resource_owner: user, application: application}}
  end

  test "#preauthorize/2 error when missing response_type", %{resource_owner: resource_owner} do
    params = Map.delete(@valid_request, "response_type")

    assert Authorization.preauthorize(resource_owner, params) == {:error, @invalid_request, :bad_request}
  end

  test "#preauthorize/2 redirect when missing response_type", %{resource_owner: resource_owner, application: application} do
    QueryHelpers.change!(application, redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path")

    params = @valid_request
             |> Map.delete("response_type")
             |> Map.merge(%{"redirect_uri" => "https://example.com/path?param=1", "state" => 40_612})

    assert Authorization.preauthorize(resource_owner, params) == {:redirect, "https://example.com/path?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+unsupported+parameter+value%2C+or+is+otherwise+malformed.&param=1&state=40612"}
  end

  test "#preauthorize/2 error when unsupported response type", %{resource_owner: resource_owner} do
    params = Map.merge(@valid_request, %{"response_type" => "invalid"})

    assert Authorization.preauthorize(resource_owner, params) == {:error, @invalid_response_type, :unprocessable_entity}
  end

  test "#preauthorize/2 redirect when unsupported response_type", %{resource_owner: resource_owner, application: application} do
    QueryHelpers.change!(application, redirect_uri: "#{application.redirect_uri}\nhttps://example.com/path")

    params = @valid_request
             |> Map.merge(%{"response_type" => "invalid"})
             |> Map.merge(%{"redirect_uri" => "https://example.com/path?param=1", "state" => 40_612})

    assert Authorization.preauthorize(resource_owner, params) == {:redirect, "https://example.com/path?error=unsupported_response_type&error_description=The+authorization+server+does+not+support+this+response+type.&param=1&state=40612"}
  end

  test "#authorize/2 error when missing response_type", %{resource_owner: resource_owner} do
    params = Map.delete(@valid_request, "response_type")

    assert Authorization.authorize(resource_owner, params) == {:error, @invalid_request, :bad_request}
  end

  test "#authorize/2 rejects when unsupported response type", %{resource_owner: resource_owner} do
    params = Map.merge(@valid_request, %{"response_type" => "invalid"})

    assert Authorization.authorize(resource_owner, params) == {:error, @invalid_response_type, :unprocessable_entity}
  end

  test "#deny/2 error when missing response_type", %{resource_owner: resource_owner} do
    params = Map.delete(@valid_request, "response_type")

    assert Authorization.deny(resource_owner, params) == {:error, @invalid_request, :bad_request}
  end

  test "#deny/2 rejects when unsupported response type", %{resource_owner: resource_owner} do
    params = Map.merge(@valid_request, %{"response_type" => "invalid"})

    assert Authorization.deny(resource_owner, params) == {:error, @invalid_response_type, :unprocessable_entity}
  end
end
