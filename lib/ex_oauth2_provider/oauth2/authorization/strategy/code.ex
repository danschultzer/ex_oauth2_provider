defmodule ExOauth2Provider.Authorization.Code do
  @moduledoc """
  Functions for dealing with authorization code flow.
  """
  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.RedirectURI
  alias ExOauth2Provider.Scopes
  alias ExOauth2Provider.Authorization.Utils.Response
  alias ExOauth2Provider.Utils.Error
  alias ExOauth2Provider.Authorization.Utils
  alias ExOauth2Provider.Authorization.Utils.Response

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
    |> Utils.load_client
    |> Utils.set_defaults
    |> validate_request
    |> check_previous_authorization
    |> reissue_grant
    |> Response.preauthorize_response
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
    |> Utils.load_client
    |> Utils.set_defaults
    |> validate_request
    |> issue_grant
    |> Response.authorize_response
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
      {:error, error} -> Error.add_error(params, error)
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
    |> Utils.load_client
    |> Utils.set_defaults
    |> validate_request
    |> Error.add_error(Error.access_denied())
    |> Response.deny_response
  end

  @doc false
  defp validate_request(%{error: _} = params), do: params
  defp validate_request(%{request: _, client: _} = params) do
    params
    |> validate_resource_owner
    |> validate_redirect_uri
    |> validate_scopes
  end

  @doc false
  defp validate_resource_owner(%{error: _} = params), do: params
  defp validate_resource_owner(%{resource_owner: resource_owner} = params) do
    case resource_owner do
      %{id: _} -> params
      _        -> Error.add_error(params, Error.invalid_request())
    end
  end

  @doc false
  defp validate_scopes(%{error: _} = params), do: params
  defp validate_scopes(%{request: %{"scope" => scopes}, client: client} = params) do
    case OauthApplications.scopes_is_subset?(client, scopes) do
      true -> params
      false -> Error.add_error(params, Error.invalid_scopes())
    end
  end

  @doc false
  defp validate_redirect_uri(%{error: _} = params), do: params
  defp validate_redirect_uri(%{request: %{"redirect_uri" => redirect_uri}, client: client} = params) do
    cond do
      RedirectURI.native_uri?(redirect_uri) -> params
      RedirectURI.valid_for_authorization?(redirect_uri, client.redirect_uri) -> params
      true -> Error.add_error(params, Error.invalid_redirect_uri())
    end
  end
  defp validate_redirect_uri(params), do: Error.add_error(params, Error.invalid_request())
end
