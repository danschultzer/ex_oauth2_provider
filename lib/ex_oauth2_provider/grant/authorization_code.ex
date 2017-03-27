defmodule ExOauth2Provider.Grant.AuthorizationCode do
  @moduledoc """
  Functions for dealing with authorization.
  """
  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.RedirectURI
  alias ExOauth2Provider.Scopes
  import ExOauth2Provider.Utils

  @doc """
  Will get an existing access token if an active one exists for the resource owner,
  client and scope.
  ## Example
    resource_owner
    |> ExOauth2Provider.Grant.AuthorizationCode.get_access_token_by_request(%{
      "client_id" => "Jf5rM8hQBc",
      "response_type" => "code"
    })
  ## Response
    {:ok, nil}                   # No token found
    {:ok, token}                 # An access token already exists
    {:ok, _, redirect}           # Ok with redirect uri
    {:error, error}              # Error occurred
    {:error, error, redirect}    # Error with redirect uri
  """
  def get_access_token_by_request(resource_owner, %{"client_id" => client_id, "response_type" => _} = request) do
    client_id
    |> load_client
    |> get_access_token_by_client_and_request(request, resource_owner)
  end
  def get_access_token_by_request(_, _), do: invalid_request()

  @doc false
  defp get_access_token_by_client_and_request(nil, _, _), do: invalid_client()
  defp get_access_token_by_client_and_request(_, _, nil), do: invalid_request()
  defp get_access_token_by_client_and_request(client, request, resource_owner) do
    request = set_defaults_on_request(client, request)

    request
    |> validate_request(client)
    |> get_token_for_resource_owner_and_client(client, resource_owner)
    |> check_scope_on_token(request["scope"])
    |> format_response(request)
  end

  @doc false
  defp get_token_for_resource_owner_and_client({:error, _} = request, _, _), do: request
  defp get_token_for_resource_owner_and_client(_, client, resource_owner) do
    token = OauthAccessTokens.get_most_recent_token(resource_owner, client)
    {:ok, token}
  end

  @doc false
  defp check_scope_on_token({:error, _} = request, _), do: request
  defp check_scope_on_token({:ok, nil} = response, _), do: response
  defp check_scope_on_token({:ok, token}, scope) do
    case ExOauth2Provider.Scopes.equal?(Scopes.to_list(token.scopes), Scopes.to_list(scope)) do
      true ->
        {:ok, token}
      false ->
        {:ok, nil}
    end
  end

  @doc """
  Authorizes a resource owner.
  This is used when a resource owner has authorized access. If successful,
  this will generate an access token grant.
  ## Example
    resource_owner
    |> ExOauth2Provider.Grant.AuthorizationCode.authorize(%{
      "client_id" => "Jf5rM8hQBc",
      "response_type" => "code",
      "scope" => "read,write",                  # Optional
      "state" => "46012",                       # Optional
      "redirect_uri" => "https://example.com/"  # Optional
    })
  ## Response
    {:ok, grant}                                       # A grant was created
    {:error, %{error: error, error_description: _}, _} # Error occurred
  """
  def authorize(resource_owner, %{"client_id" => client_id, "response_type" => _} = request) do
    client_id
    |> load_client
    |> authorize_with_client(request, resource_owner)
  end
  def authorize(_, _), do: invalid_request()

  @doc false
  defp authorize_with_client(nil, _, _), do: invalid_client()
  defp authorize_with_client(_, _, nil), do: invalid_request()
  defp authorize_with_client(client, request, resource_owner) do
    request = set_defaults_on_request(client, request)

    request
    |> validate_request(client)
    |> issue_grant(client, resource_owner)
    |> format_response(request)
  end

  @doc false
  defp issue_grant({:error, _, _} = error, _, _), do: error
  defp issue_grant(request, client, resource_owner) do
    request
    |> Map.take(["redirect_uri", "scope"])
    |> Map.new(fn {k, v} -> {String.to_atom(k), v} end) # Convert string keys to atoms
    |> Map.merge(%{expires_in: ExOauth2Provider.authorization_code_expires_in})
    |> create_crant(client, resource_owner)
  end
  defp create_crant(params, application, resource_owner),
    do: OauthAccessGrants.create_grant(resource_owner, application, params)

  @doc """
  Rejects a resource owner
  This is used when a resource owner has rejected access.
  ## Example
    resource_owner
    |> ExOauth2Provider.Grant.AuthorizationCode.deny(%{
      "client_id" => "Jf5rM8hQBc",
      "response_type" => "code"
    })
  ## Response type
    {:error, %{error: error, error_description: _}, _}
  """
  def deny(resource_owner, %{"client_id" => client_id, "response_type" => _} = request) do
    client_id
    |> load_client
    |> deny_request(request, resource_owner)
  end
  def deny(_, _), do: invalid_request()

  @doc false
  def deny_request(nil, _, _), do: invalid_client()
  def deny_request(_, _, nil), do: invalid_request()
  def deny_request(client, request, _) do
    request = set_defaults_on_request(client, request)
    format_response(access_denied(), request)
  end

  @doc false
  defp load_client(client_id) do
    OauthApplications.get_application(client_id)
  end

  @doc false
  defp validate_request(%{} = request, client) do
    request
    |> validate_redirect_uri(client.redirect_uri)
    |> validate_scopes(client.scopes)
    |> validate_response_type
  end

  @doc false
  defp set_defaults_on_request(client, request) do
    [redirect_uri | _] = String.split(client.redirect_uri)

    %{"redirect_uri" => redirect_uri,
      "scope" => client.scopes}
    |> Map.merge(request)
  end

  @doc false
  defp validate_scopes({:error, _, _} = error, _), do: error
  defp validate_scopes(%{"scope" => scope} = request, required_scopes) do
    scope
    |> Scopes.to_list
    |> Scopes.all?(Scopes.to_list(required_scopes))
    |> case do
      true -> request
      _ -> invalid_scopes()
    end
  end

  @doc false
  defp validate_redirect_uri({:error, _, _} = error, _), do: error
  defp validate_redirect_uri(%{"redirect_uri" => redirect_uri} = request, client_redirect_uri) do
    cond do
      RedirectURI.native_uri?(redirect_uri) -> request
      RedirectURI.valid_for_authorization?(redirect_uri, client_redirect_uri) -> request
      true -> invalid_redirect_uri()
    end
  end

  @doc false
  defp validate_response_type({:error, _, _} = error), do: error
  defp validate_response_type(%{"response_type" => response_type} = request) do
    case response_type == "code" do
      true  -> request
      false -> unsupported_response_type()
    end
  end

  @doc false
  defp invalid_request do
    msg = "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    {:error, %{error: :invalid_request, error_description: msg}, :bad_request}
  end

  @doc false
  defp invalid_client do
    msg = "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
    {:error, %{error: :invalid_client, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  defp invalid_scopes do
    msg = "The requested scope is invalid, unknown, or malformed."
    {:error, %{error: :invalid_scope, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  defp invalid_redirect_uri do
    msg = "The redirect uri included is not valid."
    {:error, %{error: :invalid_redirect_uri, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  defp access_denied do
    msg = "The resource owner or authorization server denied the request."
    {:error, %{error: :access_denied, error_description: msg}, :unauthorized}
  end

  @doc false
  defp unsupported_response_type do
    msg = "The authorization server does not support this response type."
    {:error, %{error: :unsupported_response_type, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  defp format_response({:ok, %OauthAccessTokens.OauthAccessToken{} = _} = response, request) do
    response
    |> append_redirect_to_response(request)
  end
  defp format_response({:ok, %OauthAccessGrants.OauthAccessGrant{} = grant} = response, request) do
    response
    |> append_redirect_to_response(request, %{code: grant.token})
  end
  defp format_response({:ok, nil} = response, _), do: response
  defp format_response({:error, error, _} = response, request) do
    response
    |> append_redirect_to_response(request, error)
  end
  defp format_response({:error, _} = response, _), # For DB errors
    do: response

  @doc false
  defp append_redirect_to_response(response, request, payload \\ %{}) do
    case can_redirect?(response, request) do
      true ->
        payload = %{"state" => request["state"]}
        |> Map.merge(payload)
        |> remove_empty_values

        response
        |> Tuple.append(uri_with_payload_from_request(request, payload))
      _ -> response
    end
  end

  @doc false
  defp can_redirect?({:error, %{error: name}, _}, %{"redirect_uri" => request_uri}) do
    name != :invalid_redirect_uri &&
    name != :invalid_client &&
    !RedirectURI.native_uri?(request_uri)
  end
  defp can_redirect?({:error, _, _}, _), do: false
  defp can_redirect?({:ok, _}, %{"redirect_uri" => request_uri}) do
    !RedirectURI.native_uri?(request_uri)
  end

  defp uri_with_payload_from_request(%{"redirect_uri" => redirect_uri}, payload),
    do: RedirectURI.uri_with_query(redirect_uri, payload)
end
