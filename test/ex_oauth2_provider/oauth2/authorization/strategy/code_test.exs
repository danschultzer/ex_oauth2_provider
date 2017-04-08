defmodule ExOauth2Provider.Authorization.CodeTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Authorization
  import ExOauth2Provider.QueryHelper
  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.Scopes

  import ExOauth2Provider.Factory
  import Ecto.Query

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

  def fixture(:application) do
    insert(:application, %{uid: @client_id, resource_owner_id: 0, scopes: "app:read app:write"})
  end

  def fixture(:resource_owner) do
    insert(:user)
  end

  def fixture(:access_token, application, scopes, resource_owner) do
    insert(:access_token, application: application, scopes: scopes, resource_owner: resource_owner)
  end

  def set_application_redirect_uri(application, uri) do
    changeset = Ecto.Changeset.change application, redirect_uri: uri
    ExOauth2Provider.repo.update! changeset
  end

  def set_application_scopes(application, scopes) do
    changeset = Ecto.Changeset.change application, scopes: scopes
    ExOauth2Provider.repo.update! changeset
  end

  def set_access_token_scopes(access_token, scopes) do
    changeset = Ecto.Changeset.change access_token, scopes: scopes
    ExOauth2Provider.repo.update! changeset
  end

  def get_last_access_grant do
    ExOauth2Provider.repo.one(from x in OauthAccessGrants.OauthAccessGrant,
      order_by: [desc: x.id], limit: 1)
  end

  setup do
    {:ok, %{resource_owner: fixture(:resource_owner), application: fixture(:application)}}
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
    access_token = fixture(:access_token, application, "app:read", resource_owner)
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

  describe "when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = set_application_scopes(application, "")

      %{resource_owner: resource_owner, application: application}
    end

    test "#preauthorize/2 with limited server scope", %{resource_owner: resource_owner, application: application} do
      request = Map.merge(@valid_request, %{"scope" => "read"})
      assert preauthorize(resource_owner, request) == {:ok, application, Scopes.to_list(request["scope"])}
    end

    test "#preauthorize/2 error when invalid server scope", %{resource_owner: resource_owner} do
      assert {:error, error, :unprocessable_entity} = preauthorize(resource_owner,  Map.merge(@valid_request, %{"scope" => "invalid"}))
      assert error == @invalid_scope
    end
  end

  test "#preauthorize/2 when previous access token with same scopes", %{resource_owner: resource_owner, application: application} do
    fixture(:access_token, application, @valid_request["scope"], resource_owner)
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

  describe "when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      application = set_application_scopes(application, "")

      %{resource_owner: resource_owner, application: application}
    end

    test "#authorize/2 error when invalid server scope", %{resource_owner: resource_owner} do
      request =  Map.merge(@valid_request, %{"scope" => "public profile"})
      assert {:error, error, :unprocessable_entity} = authorize(resource_owner, request)
      assert error == @invalid_scope
    end

    test "#authorize/2 generates grant", %{resource_owner: resource_owner} do
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
    assert get_access_grant_by_code(code).expires_in == ExOauth2Provider.authorization_code_expires_in
    assert get_access_grant_by_code(code).scopes == @valid_request["scope"]
  end

  test "#authorize/2 generates grant with redirect uri", %{resource_owner: resource_owner, application: application} do
    set_application_redirect_uri(application, "#{application.redirect_uri}\nhttp://example.com/path")

    params = Map.merge(@valid_request, %{"redirect_uri" => "http://example.com/path?param=1", "state" => 40612})

    assert {:redirect, redirect_uri} = authorize(resource_owner, params)
    assert redirect_uri == "http://example.com/path?code=#{get_last_access_grant().token}&param=1&state=40612"
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
    set_application_redirect_uri(application, "#{application.redirect_uri}\nhttp://example.com/path")
    params = Map.merge(@valid_request, %{"redirect_uri" => "http://example.com/path?param=1", "state" => 40612})

    assert {:redirect, "http://example.com/path?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request.&param=1&state=40612"} = deny(resource_owner, params)
  end
end
