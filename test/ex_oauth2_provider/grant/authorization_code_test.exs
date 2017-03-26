defmodule ExOauth2Provider.Grant.AuthorizationCodeTest do
  use ExOauth2Provider.TestCase
  doctest ExOauth2Provider

  import ExOauth2Provider.Grant.AuthorizationCode
  alias ExOauth2Provider.OauthAccessGrant

  import ExOauth2Provider.Factory

  @client_id                "Jf5rM8hQBc"
  @valid_request            %{"client_id" => @client_id, "response_type" => "code", "scope" => "read,write"}
  @invalid_redirect_uri     Map.merge(@valid_request, %{"redirect_uri" => "/invalid/path"})
  @invalid_scope            Map.merge(@valid_request, %{"scope" => "read,profile"})
  @request_invalid_client   Map.merge(@valid_request, %{"client_id" => "invalid"})
  @request_no_client        %{"response_type" => "code"}
  @request_no_response_type %{"client_id" => @client_id}
  @invalid_response_type    %{"client_id" => @client_id, "response_type" => "invalid"}

  def fixture(:application) do
    insert(:application, %{uid: @client_id, resource_owner_id: 0})
  end

  def fixture(:resource_owner) do
    insert(:user)
  end

  def add_scope_to_access_token(access_token, scope) do
    changeset = Ecto.Changeset.change access_token, scope: scope
    ExOauth2Provider.repo.update! changeset
  end

  def add_redirect_uri_to_application(application, uri) do
    changeset = Ecto.Changeset.change application, redirect_uri: uri
    ExOauth2Provider.repo.update! changeset
  end

  setup do
    {:ok, %{resource_owner: fixture(:resource_owner), application: fixture(:application)}}
  end

  test "#get_access_token_by_request/2 error when no resource owner" do
    assert {:error, error, _} = get_access_token_by_request(nil, @valid_request)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#get_access_token_by_request/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, _} = get_access_token_by_request(resource_owner, @request_invalid_client)
    assert error == %{error: :invalid_client,
      error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
    }
  end

  test "#get_access_token_by_request/2 error when missing obligatory client_id key", %{resource_owner: resource_owner} do
    assert {:error, error, _} = get_access_token_by_request(resource_owner, @request_no_client)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#get_access_token_by_request/2 error when missing obligatory response_type key", %{resource_owner: resource_owner} do
    assert {:error, error, _} = get_access_token_by_request(resource_owner, @request_no_response_type)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#get_access_token_by_request/2 no token when scopes are different", %{resource_owner: resource_owner, application: application} do
    access_token = insert(:access_token, application: application, scopes: "read", resource_owner_id: resource_owner.id)
    assert get_access_token_by_request(resource_owner, @valid_request) == {:ok, nil}

    add_scope_to_access_token(access_token, "read,write")
    request = Map.merge(@valid_request, %{scope: "read"})
    assert get_access_token_by_request(resource_owner, request) == {:ok, nil}
  end

  test "#get_access_token_by_request/2 no token when it doesn't exist", %{resource_owner: resource_owner} do
    assert get_access_token_by_request(resource_owner, @valid_request) == {:ok, nil}
  end

  test "#get_access_token_by_request/2 token when exists", %{resource_owner: resource_owner} do
    assert get_access_token_by_request(resource_owner, @valid_request) == {:ok, nil}
  end

  test "#get_access_token_by_request/2 token when exists with equal scopes", %{resource_owner: resource_owner, application: application} do
    access_token = insert(:access_token, resource_owner_id: resource_owner.id, application_id: application.id, scopes: @valid_request["scope"])
    assert get_access_token_by_request(resource_owner, @valid_request) == {:ok, access_token}
  end

  test "#authorize/2 rejects when no resource owner" do
    assert {:error, error, _} = authorize(nil, @valid_request)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#authorize/2 error when invalid client", %{resource_owner: resource_owner} do
    assert {:error, error, _} = authorize(resource_owner, @request_invalid_client)
    assert error == %{error: :invalid_client,
      error_description: "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
    }
  end

  test "#authorize/2 error when missing obligatory client_id key", %{resource_owner: resource_owner} do
    assert {:error, error, _} = authorize(resource_owner, @request_no_client)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#authorize/2 error when missing obligatory response_type key", %{resource_owner: resource_owner} do
    assert {:error, error, _} = authorize(resource_owner, @request_no_response_type)
    assert error == %{error: :invalid_request,
      error_description: "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    }
  end

  test "#authorize/2 rejects when invalid scopes", %{resource_owner: resource_owner} do
    assert {:error, error, _} = authorize(resource_owner, @invalid_scope)
    assert error == %{error: :invalid_scope,
      error_description: "The requested scope is invalid, unknown, or malformed."
    }
  end

  test "#authorize/2 rejects when invalid redirect uri", %{resource_owner: resource_owner} do
    assert {:error, error, _} = authorize(resource_owner, @invalid_redirect_uri)
    assert error == %{error: :invalid_redirect_uri,
      error_description: "The redirect uri included is not valid."
    }
  end

  test "#authorize/2 rejects when unsupported response type", %{resource_owner: resource_owner} do
    assert {:error, error, _} = authorize(resource_owner, @invalid_response_type)
    assert error == %{error: :unsupported_response_type,
      error_description: "The authorization server does not support this response type."
    }
  end

  test "#authorize/2 generates grant", %{resource_owner: resource_owner} do
    assert {:ok, %OauthAccessGrant{} = grant} = authorize(resource_owner, @valid_request)
    assert grant.resource_owner_id == resource_owner.id
  end

  test "#authorize/2 generates grant with redirection uri", %{resource_owner: resource_owner, application: application} do
    add_redirect_uri_to_application(application, "#{application.redirect_uri}\nhttp://example.com/path")
    params = Map.merge(@valid_request, %{"redirect_uri" => "http://example.com/path?param=1", "state" => 40612})

    assert {:ok, %OauthAccessGrant{} = grant, redirect_uri} = authorize(resource_owner, params)
    assert redirect_uri == "http://example.com/path?code=#{grant.token}&param=1&state=40612"
  end

  test "#deny/2", %{resource_owner: resource_owner} do
    assert {:error, error, _} = deny(resource_owner, @valid_request)
    assert error == %{error: :access_denied,
      error_description: "The resource owner or authorization server denied the request."
    }
  end

  test "#deny/2 error when no resource owner" do
    assert {:error, _, _} = deny(nil, @request_no_client)
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

    assert {:error, _, _, redirect_uri} = deny(resource_owner, params)
    assert redirect_uri == "http://example.com/path?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request.&param=1&state=40612"
  end
end
