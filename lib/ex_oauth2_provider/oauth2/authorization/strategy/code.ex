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
  alias ExOauth2Provider.{Config,
                          OauthAccessTokens,
                          OauthAccessGrants,
                          RedirectURI,
                          Authorization.Utils.Response,
                          Utils.Error,
                          Authorization.Utils,
                          Scopes}
  alias Ecto.Schema

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
  @spec preauthorize(Schema.t(), map()) :: Response.success() | Response.error() | Response.redirect() | Response.native_redirect()
  def preauthorize(resource_owner, request) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> validate_request()
    |> check_previous_authorization()
    |> reissue_grant()
    |> Response.preauthorize_response()
  end

  defp check_previous_authorization({:error, params}), do: {:error, params}
  defp check_previous_authorization({:ok, %{resource_owner: resource_owner, client: application, request: %{"scope" => scopes}} = params}) do
    case OauthAccessTokens.get_matching_token_for(resource_owner, application, scopes) do
      nil   -> {:ok, params}
      token -> {:ok, Map.put(params, :access_token, token)}
    end
  end

  defp reissue_grant({:error, params}), do: {:error, params}
  defp reissue_grant({:ok, %{access_token: _access_token} = params}), do: issue_grant({:ok, params})
  defp reissue_grant({:ok, params}), do: {:ok, params}

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
  @spec authorize(Schema.t(), map()) :: Response.success() | Response.error() | Response.redirect() | Response.native_redirect()
  def authorize(resource_owner, request) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> validate_request()
    |> issue_grant()
    |> Response.authorize_response()
  end

  defp issue_grant({:error, %{error: _error} = params}), do: {:error, params}
  defp issue_grant({:ok, %{resource_owner: resource_owner, client: application, request: request} = params}) do
    grant_params =
      request
      |> Map.take(["redirect_uri", "scope"])
      |> Map.new(fn {k, v} ->
        case k do
          "scope" -> {:scopes, v}
          _       -> {String.to_atom(k), v}
        end
      end)
      |> Map.put(:expires_in, Config.authorization_code_expires_in())

    case OauthAccessGrants.create_grant(resource_owner, application, grant_params) do
      {:ok, grant}    -> {:ok, Map.put(params, :grant, grant)}
      {:error, error} -> Error.add_error({:ok, params}, error)
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
  @spec deny(Schema.t(), map()) :: Response.error() | Response.redirect()
  def deny(resource_owner, request) do
    resource_owner
    |> Utils.prehandle_request(request)
    |> validate_request()
    |> Error.add_error(Error.access_denied())
    |> Response.deny_response()
  end

  defp validate_request({:error, params}), do: {:error, params}
  defp validate_request({:ok, params}) do
    {:ok, params}
    |> validate_resource_owner()
    |> validate_redirect_uri()
    |> validate_scopes()
  end

  defp validate_resource_owner({:ok, %{resource_owner: resource_owner} = params}) do
    case resource_owner do
      %{__struct__: _} -> {:ok, params}
      _                -> Error.add_error({:ok, params}, Error.invalid_request())
    end
  end

  defp validate_scopes({:error, params}), do: {:error, params}
  defp validate_scopes({:ok, %{request: %{"scope" => scopes}, client: client} = params}) do
    scopes        = Scopes.to_list(scopes)
    server_scopes = client.scopes |> Scopes.to_list() |> Scopes.default_to_server_scopes()

    case Scopes.all?(server_scopes, scopes) do
      true  -> {:ok, params}
      false -> Error.add_error({:ok, params}, Error.invalid_scopes())
    end
  end

  defp validate_redirect_uri({:error, params}), do: {:error, params}
  defp validate_redirect_uri({:ok, %{request: %{"redirect_uri" => redirect_uri}, client: client} = params}) do
    cond do
      RedirectURI.native_redirect_uri?(redirect_uri) ->
        {:ok, params}

      RedirectURI.valid_for_authorization?(redirect_uri, client.redirect_uri) ->
        {:ok, params}

      true ->
        Error.add_error({:ok, params}, Error.invalid_redirect_uri())
    end
  end
  defp validate_redirect_uri({:ok, params}), do: Error.add_error({:ok, params}, Error.invalid_request())
end
