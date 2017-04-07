defmodule ExOauth2Provider.Authorization.Request do
  @moduledoc """
  Functions for dealing with authorization code.
  """
  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.RedirectURI
  alias ExOauth2Provider.Scopes
  import ExOauth2Provider.Utils

  @doc """
  Will check if there's already an existing access token with same scope and client
  for the resource owner.
  ## Example
    resource_owner
    |> ExOauth2Provider.Authorization.Request.preauthorize(%{
      "client_id" => "Jf5rM8hQBc",
      "response_type" => "code"
    })
  ## Response
    {:ok, client, scopes}                                         # Show request page with client and scopes
    {:error, %{error: error, error_description: _}, http_status}  # Show error page with error and http status
    {:redirect, redirect_uri}                                     # Redirect
    {:native_redirect, %{code: code}}                             # Redirect to :show page
  """
  def preauthorize(resource_owner, %{} = request) do
    %{resource_owner: resource_owner, request: request}
    |> load_client
    |> set_defaults
    |> validate_request
    |> check_previous_authorization
    |> reissue_grant
    |> preauthorize_response
  end

  @doc false
  defp check_previous_authorization(%{error: _} = params), do: params
  defp check_previous_authorization(%{resource_owner: resource_owner, client: client, request: %{"scope" => scopes}} = params) do
    case OauthAccessTokens.get_matching_token_for(resource_owner, client, scopes) do
      nil   -> params
      token -> Map.merge(params, %{access_token: token})
    end
  end

  @doc false
  defp reissue_grant(%{error: _} = params), do: params
  defp reissue_grant(%{access_token: _} = params) do
    params
    |> issue_grant
  end
  defp reissue_grant(params), do: params

  @doc false
  defp preauthorize_response(%{client: client, request: %{"scope" => scopes}} = params) do
    case params do
      %{grant: grant} -> build_response(params, %{code: grant.token})
      %{error: error} -> build_response(params, error)
      _ -> {:ok, client, Scopes.to_list(scopes)}
    end
  end
  defp preauthorize_response(%{error: error} = params), do: build_response(params, error)

  @doc """
  This is used when a resource owner has authorized access. If successful,
  this will generate an access token grant.
  ## Example
    resource_owner
    |> ExOauth2Provider.Authorization.Request.authorize(%{
      "client_id" => "Jf5rM8hQBc",
      "response_type" => "code",
      "scope" => "read write",                  # Optional
      "state" => "46012",                       # Optional
      "redirect_uri" => "https://example.com/"  # Optional
    })
  ## Response
    {:ok, code}                                                  # A grant was generated
    {:error, %{error: error, error_description: _}, http_status} # Error occurred
    {:redirect, redirect_uri}                                    # Redirect
    {:native_redirect, %{code: code}}                            # Redirect to :show page
  """
  def authorize(resource_owner, %{} = request) do
    %{resource_owner: resource_owner, request: request}
    |> load_client
    |> set_defaults
    |> validate_request
    |> issue_grant
    |> authorize_response
  end

  @doc false
  defp issue_grant(%{error: _} = params), do: params
  defp issue_grant(%{resource_owner: resource_owner, client: application, request: request} = params) do
    grant_params = request
    |> Map.take(["redirect_uri", "scope"])
    |> Map.new(fn {k, v} ->
      case k do
        "scope" -> {:scopes, v}
        _       -> {String.to_atom(k), v}
      end
    end)
    |> Map.merge(%{expires_in: ExOauth2Provider.authorization_code_expires_in})

    case OauthAccessGrants.create_grant(resource_owner, application, grant_params) do
      {:ok, grant} -> Map.merge(params, %{grant: grant})
      {:error, error} -> add_error(params, error)
    end
  end

  @doc false
  defp authorize_response(%{} = params) do
    case params do
      %{grant: grant} -> build_response(params, %{code: grant.token})
      %{error: error} -> build_response(params, error)
    end
  end

  @doc """
  This is used when a resource owner has rejected access.
  ## Example
    resource_owner
    |> ExOauth2Provider.Authorization.Request.deny(%{
      "client_id" => "Jf5rM8hQBc",
      "response_type" => "code"
    })
  ## Response type
    {:error, %{error: error, error_description: _}, http_status} # Error occurred
    {:redirect, redirect_uri}                                    # Redirect
  """
  def deny(resource_owner, %{} = request) do
    %{resource_owner: resource_owner, request: request}
    |> load_client
    |> set_defaults
    |> validate_request
    |> add_error(access_denied())
    |> deny_response
  end

  @doc false
  defp deny_response(%{error: error} = params),
    do: build_response(params, error)

  @doc false
  defp load_client(%{request: %{"client_id" => client_id}} = params) do
    case OauthApplications.get_application(client_id) do
      nil -> add_error(params, invalid_client())
      client -> Map.merge(params, %{client: client})
    end
  end
  defp load_client(params), do: add_error(params, invalid_request())

  @doc false
  defp set_defaults(%{error: _} = params), do: params
  defp set_defaults(%{request: request, client: client} = params) do
    redirect_uri = String.split(client.redirect_uri) |> Kernel.hd

    request = %{"redirect_uri" => redirect_uri, "scope" => Scopes.default_server_scopes |> Scopes.to_string}
    |> Map.merge(request)

    params
    |> Map.merge(%{request: request})
  end

  @doc false
  defp validate_request(%{error: _} = params), do: params
  defp validate_request(%{request: _, client: _} = params) do
    params
    |> validate_resource_owner
    |> validate_response_type
    |> validate_redirect_uri
    |> validate_scopes
  end

  @doc false
  defp validate_resource_owner(%{error: _} = params), do: params
  defp validate_resource_owner(%{resource_owner: resource_owner} = params) do
    case resource_owner do
      %{id: _} -> params
      _ -> add_error(params, invalid_request())
    end
  end

  @doc false
  defp validate_scopes(%{error: _} = params), do: params
  defp validate_scopes(%{request: %{"scope" => scopes}, client: client} = params) do
    client
    |> all_scopes
    |> Scopes.all?(scopes |> Scopes.to_list)
    |> case do
      true -> params
      _    -> add_error(params, invalid_scopes())
    end
  end

  @doc false
  defp all_scopes(%OauthApplications.OauthApplication{scopes: application_scopes}) do
    case application_scopes do
      nil -> Scopes.server_scopes
      ""  -> Scopes.server_scopes
      _   -> application_scopes |> Scopes.to_list
    end
  end

  @doc false
  defp validate_redirect_uri(%{error: _} = params), do: params
  defp validate_redirect_uri(%{request: %{"redirect_uri" => redirect_uri}, client: client} = params) do
    cond do
      RedirectURI.native_uri?(redirect_uri) -> params
      RedirectURI.valid_for_authorization?(redirect_uri, client.redirect_uri) -> params
      true -> add_error(params, invalid_redirect_uri())
    end
  end
  defp validate_redirect_uri(params), do: add_error(params, invalid_request())

  @doc false
  defp validate_response_type(%{error: _} = params), do: params
  defp validate_response_type(%{request: %{"response_type" => response_type}} = params) do
    case response_type == "code" do
      true  -> params
      false -> add_error(params, unsupported_response_type())
    end
  end
  defp validate_response_type(params), do: add_error(params, invalid_request())

  @doc false
  defp add_error(%{error: _} = params, _), do: params
  defp add_error(params, {:error, error, http_status}) do
    Map.merge(params, %{error: error, error_http_status: http_status})
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
  defp build_response(%{request: request} = params, payload) do
    payload = add_state(payload, request)

    case can_redirect?(params) do
      true -> build_redirect_response(params, payload)
      _ -> build_standard_response(params, payload)
    end
  end
  defp add_state(payload, request) do
    case request["state"] do
      nil -> payload
      state ->
        %{"state" => state}
        |> Map.merge(payload)
        |> remove_empty_values
    end
  end

  @doc false
  defp build_redirect_response(%{request: %{"redirect_uri" => redirect_uri}}, payload) do
    case RedirectURI.native_uri?(redirect_uri) do
      true -> {:native_redirect, payload}
      _    -> {:redirect, RedirectURI.uri_with_query(redirect_uri, payload)}
    end
  end

  @doc false
  defp build_standard_response(%{grant: _}, payload) do
    {:ok, payload}
  end
  defp build_standard_response(%{error: error, error_http_status: error_http_status}, _) do
    {:error, error, error_http_status}
  end
  defp build_standard_response(%{error: error}, _) do # For DB errors
    {:error, error, :bad_request}
  end

  @doc false
  defp can_redirect?(%{error: %{error: error_name}, request: %{"redirect_uri" => redirect_uri}}) do
    error_name != :invalid_redirect_uri &&
    error_name != :invalid_client &&
    !RedirectURI.native_uri?(redirect_uri)
  end
  defp can_redirect?(%{error: _}), do: false
  defp can_redirect?(%{request: %{}}), do: true
end
