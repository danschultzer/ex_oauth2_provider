defmodule ExOauth2Provider.Authorization.Implicit do
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.Utils.Error
  alias ExOauth2Provider.Authorization.Utils
  alias ExOauth2Provider.Authorization.Utils.Response
  alias ExOauth2Provider.OauthApplications.OauthApplication

  import ExOauth2Provider.Authorization.Utils.Helpers

  @doc """
  Validates an implicit flow request.

  Will check if there's already an existing access token with same scope and client
  for the resource owner.

  With optional `prompt` parameter set to `false` it will autorize the client without prompting
  the resource owner.

  ## Example
      resource_owner
      |> ExOauth2Provider.Authorization.preauthorize(%{
        "client_id" => "Jf5rM8hQBc",
        "response_type" => "token",
        "prompt" => false
      })
  ## Response
      {:ok, client, scopes}                                         # Show request page with client and scopes
      {:error, %{error: error, error_description: _}, http_status}  # Show error page with error and http status
      {:redirect, redirect_uri}                                     # Redirect
      {:native_redirect, %{token: token}}                           # Redirect to :show page
  """
  @spec preauthorize(Ecto.Schema.t(), Map.t()) ::
          {:ok, %OauthApplication{}, [String.t()]}
          | {:error, Map.t(), integer}
          | {:redirect, String.t()}
          | {:native_redirect, %{access_token: String.t()}}
  def preauthorize(resource_owner, request) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> validate_request()
    |> check_previous_authorization()
    |> authorize_without_prompt()
    |> Response.preauthorize_response()
  end

  defp authorize_without_prompt(%{access_token: _} = params) do
    params
  end

  defp authorize_without_prompt(%{request: %{"prompt" => "false"}} = params) do
    params |> create_access_token()
  end

  defp authorize_without_prompt(params) do
    params
  end

  @doc """
  Authorizes an implicit flow request.

  This is used when a resource owner has authorized access. If successful,
  this will generate an access token.

  ## Example
      resource_owner
      |> ExOauth2Provider.Authorization.authorize(%{
        "client_id" => "Jf5rM8hQBc",
        "response_type" => "token",
        "scope" => "read write",                  # Optional
        "state" => "46012",                       # Optional
        "redirect_uri" => "https://example.com/"  # Optional
      })
  ## Response
      {:ok, access_token}                                          # Access token was generated
      {:error, %{error: error, error_description: _}, http_status} # Error occurred
      {:redirect, redirect_uri}                                    # Redirect
      {:native_redirect, %{access_token: acesss_token}}            # Redirect to :show page
  """
  @spec authorize(Ecto.Schema.t(), Map.t()) ::
          {:ok, String.t()}
          | {:error, Map.t(), integer}
          | {:redirect, String.t()}
          | {:native_redirect, %{access_token: String.t()}}
  def authorize(resource_owner, request) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> validate_request()
    |> create_access_token()
    |> Response.authorize_response()
  end

  defp create_access_token(%{error: _error} = params), do: params

  defp create_access_token(
         %{resource_owner: resource_owner, client: application, request: %{"scope" => scopes}} =
           params
       ) do
    case OauthAccessTokens.create_token(resource_owner, %{
           application: application,
           scopes: scopes,
           expires_in: ExOauth2Provider.Config.access_token_expires_in()
         }) do
      {:ok, token} -> Map.put(params, :access_token, token)
      {:error, error} -> Error.add_error(params, error)
    end
  end

  @doc """
  Rejects an implicit flow request.

  This is used when a resource owner has rejected access.

  ## Example
      resource_owner
      |> ExOauth2Provider.Authorization.deny(%{
        "client_id" => "Jf5rM8hQBc",
        "response_type" => "token"
      })
  ## Response type
      {:error, %{error: error, error_description: _}, http_status} # Error occurred
      {:redirect, redirect_uri}                                    # Redirect
  """
  @spec deny(Ecto.Schema.t(), Map.t()) ::
          {:error, Map.t(), integer}
          | {:redirect, String.t()}
  def deny(resource_owner, request) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> validate_request()
    |> Error.add_error(Error.access_denied())
    |> Response.deny_response()
  end
end
