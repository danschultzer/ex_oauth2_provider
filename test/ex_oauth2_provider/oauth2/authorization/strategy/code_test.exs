defmodule ExOauth2Provider.Authorization.CodeTest do
  use ExOauth2Provider.TestCase

  import ExOauth2Provider.Test.Fixture
  import ExOauth2Provider.Test.QueryHelper
  import ExOauth2Provider.Authorization

  alias ExOauth2Provider.Scopes

  @client_id                "Jf5rM8hQBc"
  @valid_request            %{"client_id" => @client_id, "response_type" => "code", "scope" => "app:read app:write"}
  @invalid_request          %{error: :invalid_request,
                              error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
                            }
  @invalid_client           %{error: :invalid_client,
                              error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
                            }
  @invalid_scope            %{error: :invalid_scope,
                              error_description: "The requested scope is invalid, unknown, or malformed."
                            }
  @invalid_redirect_uri     %{error: :invalid_redirect_uri,
                              error_description: "The redirect uri included is not valid."
                            }
  @access_denied            %{error: :access_denied,
                              error_description: "The resource owner or authorization server denied the request."
                            }

  setup do
    resource_owner = fixture(:user)
    application = fixture(:application, fixture(:user), %{uid: @client_id, scopes: "app:read app:write"})
    {:ok, %{resource_owner: resource_owner, application: application}}
  end

  test "#preauthorize/2 error when no resource owner" do
    assert {:error, error, :bad_request} = preauthorize(nil, @valid_request)
    assert error == @invalid_request
  end

  test "#preauthorize/2 error when no client_id", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = preauthorize(resource_owner, Map.delete(@valid_request, "client_id"))
    assert error == @invalid_request
  end

  test "#preauthorize/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} = preauthorize(resource_owner, Map.merge(@valid_request, %{"client_id" => "invalid"}))
    assert error == @invalid_client
  end

  test "#preauthorize/2", %{resource_owner: resource_owner, application: application} do
    assert preauthorize(resource_owner, @valid_request) == {:ok, application, Scopes.to_list(@valid_request["scope"])}
  end

  test "#preauthorize/2 when previous access token with different application scopes", %{resource_owner: resource_owner, application: application} do
    access_token = fixture(:access_token, resource_owner, %{application: application, scopes: "app:read"})
    assert preauthorize(resource_owner, @valid_request) == {:ok, application, Scopes.to_list(@valid_request["scope"])}

    set_access_token_scopes(access_token, "app:read app:write")

    request = Map.merge(@valid_request, %{"scope" => "app:read"})
    assert preauthorize(resource_owner, request) == {:ok, application, Scopes.to_list(request["scope"])}
  end

  test "#preauthorize/2 with limited scope", %{resource_owner: resource_owner, application: application} do
    request = Map.merge(@valid_request, %{"scope" => "app:read"})
    assert preauthorize(resource_owner, request) == {:ok, application, ["app:read"]}
  end

  test "#preauthorize/2 error when invalid scope", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_request, %{"scope" => "app:invalid"})
    assert {:error, error, :unprocessable_entity} = preauthorize(resource_owner, request)
    assert error == @invalid_scope
  end

  describe "#preauthorize/2 when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = set_application_scopes(application, "")

      %{resource_owner: resource_owner, application: application}
    end

    test "with limited server scope", %{resource_owner: resource_owner, application: application} do
      request = Map.merge(@valid_request, %{"scope" => "read"})
      assert {:ok, application, ["read"]} == preauthorize(resource_owner, request)
    end

    test "error when invalid server scope", %{resource_owner: resource_owner} do
      assert {:error, error, :unprocessable_entity} = preauthorize(resource_owner,  Map.merge(@valid_request, %{"scope" => "invalid"}))
      assert error == @invalid_scope
    end
  end

  test "#preauthorize/2 when previous access token with same scopes", %{resource_owner: resource_owner, application: application} do
    fixture(:access_token, resource_owner, %{application: application, scopes: @valid_request["scope"]})
    assert preauthorize(resource_owner, @valid_request) == {:native_redirect, %{code: get_last_access_grant().token}}
  end

  test "#authorize/2 rejects when no resource owner" do
    assert {:error, error, :bad_request} = authorize(nil, @valid_request)
    assert error == @invalid_request
  end

  test "#authorize/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} = authorize(resource_owner, Map.merge(@valid_request, %{"client_id" => "invalid"}))
    assert error == @invalid_client
  end

  test "#authorize/2 error when no client_id", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = authorize(resource_owner, Map.delete(@valid_request, "client_id"))
    assert error == @invalid_request
  end

  test "#authorize/2 error when invalid scope", %{resource_owner: resource_owner} do
    request =  Map.merge(@valid_request, %{"scope" => "app:read app:profile"})
    assert {:error, error, :unprocessable_entity} = authorize(resource_owner, request)
    assert error == @invalid_scope
  end

  describe "#authorize/2 when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = set_application_scopes(application, "")

      %{resource_owner: resource_owner, application: application}
    end

    test "error when invalid server scope", %{resource_owner: resource_owner} do
      request =  Map.merge(@valid_request, %{"scope" => "public profile"})
      assert {:error, error, :unprocessable_entity} = authorize(resource_owner, request)
      assert error == @invalid_scope
    end

    test "generates grant", %{resource_owner: resource_owner} do
      request =  Map.merge(@valid_request, %{"scope" => "public"})
      assert {:native_redirect, %{code: code}} = authorize(resource_owner, request)
      assert get_access_grant_by_code(code).resource_owner_id == resource_owner.id
    end
  end

  test "#authorize/2 error when invalid redirect uri", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} = authorize(resource_owner, Map.merge(@valid_request, %{"redirect_uri" => "/invalid/path"}))
    assert error == @invalid_redirect_uri
  end

  test "#authorize/2 generates grant", %{resource_owner: resource_owner} do
    assert {:native_redirect, %{code: code}} = authorize(resource_owner, @valid_request)
    assert get_access_grant_by_code(code).resource_owner_id == resource_owner.id
    assert get_access_grant_by_code(code).expires_in == ExOauth2Provider.Config.authorization_code_expires_in
    assert get_access_grant_by_code(code).scopes == @valid_request["scope"]
  end

  test "#authorize/2 generates grant with redirect uri", %{resource_owner: resource_owner, application: application} do
    set_application_redirect_uri(application, "#{application.redirect_uri}\nhttps://example.com/path")

    params = Map.merge(@valid_request, %{"redirect_uri" => "https://example.com/path?param=1", "state" => 40612})

    assert {:redirect, redirect_uri} = authorize(resource_owner, params)
    assert redirect_uri == "https://example.com/path?code=#{get_last_access_grant().token}&param=1&state=40612"
  end

  test "#deny/2 error when no resource owner" do
    assert {:error, _, _} = deny(nil, @valid_request)
  end

  test "#deny/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, :unprocessable_entity} = deny(resource_owner, Map.merge(@valid_request, %{"client_id" => "invalid"}))
    assert error == @invalid_client
  end

  test "#deny/2 error when no client_id", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = deny(resource_owner, Map.delete(@valid_request, "client_id"))
    assert error == @invalid_request
  end

  test "#deny/2", %{resource_owner: resource_owner} do
    assert {:error, error, :unauthorized} = deny(resource_owner, @valid_request)
    assert error == @access_denied
  end

  test "#deny/2 with redirection uri", %{application: application, resource_owner: resource_owner} do
    set_application_redirect_uri(application, "#{application.redirect_uri}\nhttps://example.com/path")
    params = Map.merge(@valid_request, %{"redirect_uri" => "https://example.com/path?param=1", "state" => 40612})

    assert {:redirect, "https://example.com/path?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request.&param=1&state=40612"} = deny(resource_owner, params)
  end
end
