defmodule ExOauth2Provider.Grant.AuthorizationCodeTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Grant.AuthorizationCode
  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.Scopes

  import ExOauth2Provider.Factory
  import Ecto.Query

  @client_id                "Jf5rM8hQBc"
  @valid_request            %{"client_id" => @client_id, "response_type" => "code", "scope" => "app:read app:write"}
  @invalid_redirect_uri     Map.merge(@valid_request, %{"redirect_uri" => "/invalid/path"})
  @request_invalid_client   Map.merge(@valid_request, %{"client_id" => "invalid"})
  @request_no_client        %{"response_type" => "code"}
  @request_no_response_type %{"client_id" => @client_id}
  @invalid_response_type    %{"client_id" => @client_id, "response_type" => "invalid"}

  def fixture(:application) do
    insert(:application, %{uid: @client_id, resource_owner_id: 0, scopes: "app:read app:write"})
  end

  def fixture(:resource_owner) do
    insert(:user)
  end

  def add_redirect_uri_to_application(application, uri) do
    changeset = Ecto.Changeset.change application, redirect_uri: uri
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
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#preauthorize/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = preauthorize(resource_owner, @request_invalid_client)
    assert error == %{error: :invalid_client,
      error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
    }
  end

  test "#preauthorize/2 error when missing obligatory client_id key", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = preauthorize(resource_owner, @request_no_client)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#preauthorize/2 error when missing obligatory response_type key", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = preauthorize(resource_owner, @request_no_response_type)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#preauthorize/2", %{resource_owner: resource_owner, application: application} do
    assert preauthorize(resource_owner, @valid_request) == {:ok, application, Scopes.to_list(@valid_request["scope"])}
  end

  test "#preauthorize/2 when previous access token with different scopes", %{resource_owner: resource_owner, application: application} do
    access_token = insert(:access_token, application: application, scopes: "app:read", resource_owner_id: resource_owner.id)
    assert preauthorize(resource_owner, @valid_request) == {:ok, application, Scopes.to_list(@valid_request["scope"])}

    changeset = Ecto.Changeset.change access_token, scopes: "app:read app:write"
    ExOauth2Provider.repo.update! changeset

    request = Map.merge(@valid_request, %{"scope" => "app:read"})
    assert preauthorize(resource_owner, request) == {:ok, application, Scopes.to_list(request["scope"])}
  end

  test "#preauthorize/2 with limited scope", %{resource_owner: resource_owner, application: application} do
    request = Map.merge(@valid_request, %{"scope" => "app:read"})
    assert preauthorize(resource_owner, request) == {:ok, application, Scopes.to_list(request["scope"])}
  end

  test "#preauthorize/2 when previous access token with same scopes", %{resource_owner: resource_owner, application: application} do
    insert(:access_token, resource_owner_id: resource_owner.id, application_id: application.id, scopes: @valid_request["scope"])
    assert preauthorize(resource_owner, @valid_request) == {:native_redirect, %{code: get_last_access_grant().token}}
  end

  test "#authorize/2 rejects when no resource owner" do
    assert {:error, error, :bad_request} = authorize(nil, @valid_request)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#authorize/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = authorize(resource_owner, @request_invalid_client)
    assert error == %{error: :invalid_client,
      error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
    }
  end

  test "#authorize/2 error when missing obligatory client_id key", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = authorize(resource_owner, @request_no_client)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#authorize/2 error when missing obligatory response_type key", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = authorize(resource_owner, @request_no_response_type)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#authorize/2 rejects when has unknown scope", %{resource_owner: resource_owner} do
    request =  Map.merge(@valid_request, %{"scope" => "app:read app:profile"})
    assert {:error, error, :bad_request} = authorize(resource_owner, request)
    assert error == %{error: :invalid_scope,
      error_description: "The requested scope is invalid, unknown, or malformed."
    }
  end

  describe "when application has no scope" do
    setup %{resource_owner: resource_owner, application: application} do
      changeset = Ecto.Changeset.change application, scopes: ""
      ExOauth2Provider.repo.update! changeset

      %{resource_owner: resource_owner, application: application}
    end

    test "#authorize/2 rejects when has unknown scope", %{resource_owner: resource_owner} do
      request =  Map.merge(@valid_request, %{"scope" => "public profile"})
      assert {:error, error, :bad_request} = authorize(resource_owner, request)
      assert error == %{error: :invalid_scope,
        error_description: "The requested scope is invalid, unknown, or malformed."
      }
    end

    test "#authorize/2 generates grant", %{resource_owner: resource_owner} do
      request =  Map.merge(@valid_request, %{"scope" => "public"})
      assert {:native_redirect, %{code: code}} = authorize(resource_owner, request)
      assert OauthAccessGrants.get_grant!(code).resource_owner_id == resource_owner.id
    end
  end

  test "#authorize/2 rejects when invalid redirect uri", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = authorize(resource_owner, @invalid_redirect_uri)
    assert error == %{error: :invalid_redirect_uri,
      error_description: "The redirect uri included is not valid."
    }
  end

  test "#authorize/2 rejects when unsupported response type", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = authorize(resource_owner, @invalid_response_type)
    assert error == %{error: :unsupported_response_type,
      error_description: "The authorization server does not support this response type."
    }
  end

  test "#authorize/2 generates grant", %{resource_owner: resource_owner} do
    assert {:native_redirect, %{code: code}} = authorize(resource_owner, @valid_request)
    assert OauthAccessGrants.get_grant!(code).resource_owner_id == resource_owner.id
  end

  test "#authorize/2 generates grant with redirection uri", %{resource_owner: resource_owner, application: application} do
    add_redirect_uri_to_application(application, "#{application.redirect_uri}\nhttp://example.com/path")
    params = Map.merge(@valid_request, %{"redirect_uri" => "http://example.com/path?param=1", "state" => 40612})

    assert {:redirect, redirect_uri} = authorize(resource_owner, params)
    assert redirect_uri == "http://example.com/path?code=#{get_last_access_grant().token}&param=1&state=40612"
  end

  test "#deny/2", %{resource_owner: resource_owner} do
    assert {:error, error, :bad_request} = deny(resource_owner, @valid_request)
    assert error == %{error: :access_denied,
      error_description: "The resource owner or authorization server denied the request."
    }
  end

  test "#deny/2 error when no resource owner" do
    assert {:error, _, _} = deny(nil, @valid_request)
  end

  test "#deny/2 error when missing obligatory client_id key", %{resource_owner: resource_owner} do
    assert {:error, _, _} = deny(resource_owner, @request_no_client)
  end

  test "#deny/2 error when missing obligatory response_type key", %{resource_owner: resource_owner} do
    assert {:error, _, _} = deny(resource_owner, @request_no_response_type)
  end

  test "#deny/2 with redirection uri", %{application: application, resource_owner: resource_owner} do
    add_redirect_uri_to_application(application, "#{application.redirect_uri}\nhttp://example.com/path")
    params = Map.merge(@valid_request, %{"redirect_uri" => "http://example.com/path?param=1", "state" => 40612})

    assert {:redirect, "http://example.com/path?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request.&param=1&state=40612"} = deny(resource_owner, params)
  end
end
