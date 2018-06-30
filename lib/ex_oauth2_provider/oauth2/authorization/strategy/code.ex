defmodule ExOauth2Provider.Authorization.Code do
  @moduledoc """
  Methods for authorization code flow.

  The flow consists of three method calls:

  1. `preauthorize(resource_owner, request)`

  This validates the request. If a resource owner already have been
  authenticated previously it'll respond with a redirect tuple.

  2. `authorize(resource_owner, request)`

  This confirms a resource owner authorization, and will generate an access
  token.

  3. `deny(resource_owner, request)`

  This rejects a resource owner authorization.

  ---

  In a controller it could look like this:

  ```elixir
  alias ExOauth2Provider.Authorization

  def new(conn, params) do
    case Authorization.preauthorize(current_resource_owner(conn), params) do
      {:ok, client, scopes} ->
        render(conn, "new.html", params: params, client: client, scopes: scopes)
      {:native_redirect, %{code: code}} ->
        redirect(conn, to: oauth_authorization_path(conn, :show, code))
      {:redirect, redirect_uri} ->
        redirect(conn, external: redirect_uri)
      {:error, error, status} ->
        conn
        |> put_status(status)
        |> render("error.html", error: error)
    end
  end

  def create(conn, params) do
    conn
    |> current_resource_owner
    |> Authorization.authorize(params)
    |> redirect_or_render(conn)
  end

  def delete(conn, params) do
    conn
    |> current_resource_owner
    |> Authorization.deny(params)
    |> redirect_or_render(conn)
  end
  ```
  """
  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.Authorization.Utils.Response
  alias ExOauth2Provider.Utils.Error
  alias ExOauth2Provider.Authorization.Utils
  alias ExOauth2Provider.Authorization.Utils.Response
  alias ExOauth2Provider.OauthApplications.OauthApplication

  import ExOauth2Provider.Authorization.Utils.Helpers

  @doc """
  Validates an authorization code flow request.

  Will check if there's already an existing access token with same scope and client
  for the resource owner.

  ## Example
      resource_owner
      |> ExOauth2Provider.Authorization.preauthorize(%{
        "client_id" => "Jf5rM8hQBc",
        "response_type" => "code"
      })
  ## Response
      {:ok, client, scopes}                                         # Show request page with client and scopes
      {:error, %{error: error, error_description: _}, http_status}  # Show error page with error and http status
      {:redirect, redirect_uri}                                     # Redirect
      {:native_redirect, %{code: code}}                             # Redirect to :show page
  """
  @spec preauthorize(Ecto.Schema.t, Map.t) :: {:ok, %OauthApplication{}, [String.t]} |
                                              {:error, Map.t, integer} |
                                              {:redirect, String.t} |
                                              {:native_redirect, %{code: String.t}}
  def preauthorize(resource_owner, %{} = request) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> validate_request()
    |> check_previous_authorization()
    |> reissue_grant()
    |> Response.preauthorize_response()
  end

  defp reissue_grant(%{error: _error} = params), do: params
  defp reissue_grant(%{access_token: _access_token} = params), do: issue_grant(params)
  defp reissue_grant(params), do: params

  @doc """
  Authorizes an authorization code flow request.

  This is used when a resource owner has authorized access. If successful,
  this will generate an access token grant.

  ## Example
      resource_owner
      |> ExOauth2Provider.Authorization.authorize(%{
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
  @spec authorize(Ecto.Schema.t, Map.t) :: {:ok, String.t} |
                                           {:error, Map.t, integer} |
                                           {:redirect, String.t} |
                                           {:native_redirect, %{code: String.t}}
  def authorize(resource_owner, request) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> validate_request()
    |> issue_grant()
    |> Response.authorize_response()
  end

  defp issue_grant(%{error: _error} = params), do: params
  defp issue_grant(%{resource_owner: resource_owner, client: application, request: request} = params) do
    grant_params = request
    |> Map.take(["redirect_uri", "scope"])
    |> Map.new(fn {k, v} ->
         case k do
           "scope" -> {:scopes, v}
           _       -> {String.to_atom(k), v}
         end
       end)
    |> Map.put(:expires_in, ExOauth2Provider.Config.authorization_code_expires_in())

    case OauthAccessGrants.create_grant(resource_owner, application, grant_params) do
      {:ok, grant}    -> Map.put(params, :grant, grant)
      {:error, error} -> Error.add_error(params, error)
    end
  end


  @doc """
  Rejects an authorization code flow request.

  This is used when a resource owner has rejected access.

  ## Example
      resource_owner
      |> ExOauth2Provider.Authorization.deny(%{
        "client_id" => "Jf5rM8hQBc",
        "response_type" => "code"
      })
  ## Response type
      {:error, %{error: error, error_description: _}, http_status} # Error occurred
      {:redirect, redirect_uri}                                    # Redirect
  """
  @spec deny(Ecto.Schema.t, Map.t) :: {:error, Map.t, integer} |
                                      {:redirect, String.t}
  def deny(resource_owner, request) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> validate_request()
    |> Error.add_error(Error.access_denied())
    |> Response.deny_response()
  end
end
