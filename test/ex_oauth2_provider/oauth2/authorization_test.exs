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

  def set_application_redirect_uri(application, uri) do
    changeset = Ecto.Changeset.change application, redirect_uri: uri
    ExOauth2Provider.repo.update! changeset
  end

  setup do
    user = insert(:user)
    application = insert(:application, %{uid: @client_id, secret: @client_secret, resource_owner_id: user.id})
    {:ok, %{resource_owner: user, application: application}}
  end

  test "#preauthorize/2 error when missing response_type", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = preauthorize(resource_owner, Map.delete(@valid_request, "response_type"))
    assert error == @invalid_request
  end

  test "#preauthorize/2 redirect when missing response_type", %{resource_owner: resource_owner, application: application} do
    set_application_redirect_uri(application, "#{application.redirect_uri}\nhttp://example.com/path")
    params = @valid_request
    |> Map.delete("response_type")
    |> Map.merge(%{"redirect_uri" => "http://example.com/path?param=1", "state" => 40612})

    assert preauthorize(resource_owner, params) == {:redirect,
             "http://example.com/path?error=invalid_request&error_description=The+request+is+missing+a+required+parameter%2C+includes+an+unsupported+parameter+value%2C+or+is+otherwise+malformed.&param=1&state=40612"}
  end

  test "#preauthorize/2 error when unsupported response type", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} = preauthorize(resource_owner, Map.merge(@valid_request, %{"response_type" => "invalid"}))
    assert error == @invalid_response_type
  end

  test "#preauthorize/2 redirect when unsupported response_type", %{resource_owner: resource_owner, application: application} do
    set_application_redirect_uri(application, "#{application.redirect_uri}\nhttp://example.com/path")
    params = @valid_request
    |> Map.merge(%{"response_type" => "invalid"})
    |> Map.merge(%{"redirect_uri" => "http://example.com/path?param=1", "state" => 40612})

    assert preauthorize(resource_owner, params) == {:redirect, "http://example.com/path?error=unsupported_response_type&error_description=The+authorization+server+does+not+support+this+response+type.&param=1&state=40612"}
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
