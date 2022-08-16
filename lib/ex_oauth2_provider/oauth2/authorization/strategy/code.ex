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
  alias ExOauth2Provider.{
    Config,
    AccessTokens,
    AccessGrants,
    Authorization.Utils,
    Authorization.Utils.Response,
    RedirectURI,
    Scopes,
    Utils.Error,
    Utils.Validation}
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
      }, otp_app: :my_app)

  ## Response
      {:ok, client, scopes}                                         # Show request page with client and scopes
      {:error, %{error: error, error_description: _}, http_status}  # Show error page with error and http status
      {:redirect, redirect_uri}                                     # Redirect
      {:native_redirect, %{code: code}}                             # Redirect to :show page
  """
  @spec preauthorize(Schema.t(), map(), keyword()) :: Response.success() | Response.error() | Response.redirect() | Response.native_redirect()
  def preauthorize(resource_owner, request, config \\ []) do
    resource_owner
    |> Utils.prehandle_request(request, config)
    |> validate_request(config)
    |> check_previous_authorization(config)
    |> reissue_grant(config)
    |> Response.preauthorize_response(config)
  end

  defp check_previous_authorization({:error, params}, _config), do: {:error, params}
  defp check_previous_authorization({:ok, %{resource_owner: resource_owner, client: application, request: %{"scope" => scopes}} = params}, config) do
    case AccessTokens.get_token_for(resource_owner, application, scopes, config) do
      nil   -> {:ok, params}
      token -> {:ok, Map.put(params, :access_token, token)}
    end
  end

  defp reissue_grant({:error, params}, _config), do: {:error, params}
  defp reissue_grant({:ok, %{access_token: _access_token} = params}, config), do: issue_grant({:ok, params}, config)
  defp reissue_grant({:ok, params}, _config), do: {:ok, params}

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
      }, otp_app: :my_app)

  ## Response
      {:ok, code}                                                  # A grant was generated
      {:error, %{error: error, error_description: _}, http_status} # Error occurred
      {:redirect, redirect_uri}                                    # Redirect
      {:native_redirect, %{code: code}}                            # Redirect to :show page
  """
  @spec authorize(Schema.t(), map(), keyword()) :: Response.success() | Response.error() | Response.redirect() | Response.native_redirect()
  def authorize(resource_owner, request, config \\ []) do
    resource_owner
    |> Utils.prehandle_request(request, config)
    |> validate_request(config)
    |> issue_grant(config)
    |> Response.authorize_response(config)
  end

  defp issue_grant({:error, %{error: _error} = params}, _config), do: {:error, params}
  defp issue_grant({:ok, %{resource_owner: resource_owner, client: application, request: request} = params}, config) do
    filtered_request = if Config.use_pkce?(config) do
      Map.merge(%{"code_challenge_method" => "plain"}, request)
      |> Map.take(["redirect_uri", "scope", "code_challenge", "code_challenge_method"])
      |> Map.update!("code_challenge", fn v -> String.replace(v, "=", "") end)
    else
      Map.take(request, ["redirect_uri", "scope"])
    end

    grant_params = filtered_request
      |> Map.new(fn {k, v} ->
        case k do
          "scope" -> {:scopes, v}
          _       -> {String.to_atom(k), v}
        end
      end)
      |> Map.put(:expires_in, Config.authorization_code_expires_in(config))

    case AccessGrants.create_grant(resource_owner, application, grant_params, config) do
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
      }, otp_app: :my_app)

  ## Response type
      {:error, %{error: error, error_description: _}, http_status} # Error occurred
      {:redirect, redirect_uri}                                    # Redirect
  """
  @spec deny(Schema.t(), map(), keyword()) :: Response.error() | Response.redirect()
  def deny(resource_owner, request, config \\ []) do
    resource_owner
    |> Utils.prehandle_request(request, config)
    |> validate_request(config)
    |> Error.add_error(Error.access_denied())
    |> Response.deny_response(config)
  end

  defp validate_request({:error, params}, _config), do: {:error, params}
  defp validate_request({:ok, params}, config) do
    {:ok, params}
    |> validate_resource_owner()
    |> validate_redirect_uri(config)
    |> validate_scopes(config)
    |> validate_pkce(Config.use_pkce?(config))
  end

  defp validate_resource_owner({:ok, %{resource_owner: resource_owner} = params}) do
    case resource_owner do
      %{__struct__: _} -> {:ok, params}
      _                -> Error.add_error({:ok, params}, Error.invalid_request())
    end
  end

  defp validate_scopes({:error, params}, _config), do: {:error, params}
  defp validate_scopes({:ok, %{request: %{"scope" => scopes}, client: client} = params}, config) do
    scopes        = Scopes.to_list(scopes)
    server_scopes =
      client.scopes
      |> Scopes.to_list()
      |> Scopes.default_to_server_scopes(config)

    case Scopes.all?(server_scopes, scopes) do
      true  -> {:ok, params}
      false -> Error.add_error({:ok, params}, Error.invalid_scopes())
    end
  end

  defp validate_redirect_uri({:error, params}, _config), do: {:error, params}
  defp validate_redirect_uri({:ok, %{request: %{"redirect_uri" => redirect_uri}, client: client} = params}, config) do
    cond do
      RedirectURI.native_redirect_uri?(redirect_uri, config) ->
        {:ok, params}

      RedirectURI.valid_for_authorization?(redirect_uri, client.redirect_uri, config) ->
        {:ok, params}

      true ->
        Error.add_error({:ok, params}, Error.invalid_redirect_uri())
    end
  end
  defp validate_redirect_uri({:ok, params}, _config), do: Error.add_error({:ok, params}, Error.invalid_request())

  defp validate_pkce({:error, params}, _use_pkce?), do: {:error, params}
  defp validate_pkce({:ok, params}, false), do: {:ok, params}
  defp validate_pkce({:ok, %{request: %{"code_challenge" => code_challenge} = request} = params}, true) do
    code_challenge_method = Map.get(request, "code_challenge_method", "plain")

    if valid_code_challenge_format?(code_challenge, code_challenge_method) do
      {:ok, params}
    else
      Error.add_error({:ok, params}, Error.invalid_request())
    end
  end
  defp validate_pkce({:ok, params}, true), do: Error.add_error({:ok, params}, Error.invalid_request()) # missing code_challenge

  @sha256_byte_size 256/8

  defp valid_code_challenge_format?(nil, _code_challenge_method), do: false
  defp valid_code_challenge_format?(code_challenge, "plain"), do: Validation.valid_code_verifier_format?(code_challenge)
  defp valid_code_challenge_format?(code_challenge, "S256") do
    case Base.url_decode64(code_challenge, padding: false) do # padding '=' deliberately accepted
      {:ok, bin} -> byte_size(bin) == @sha256_byte_size
      :error -> false
    end
  end
  defp valid_code_challenge_format?(_code_challenge, _code_challenge_method), do: false
end
