defmodule ExOauth2Provider.Token.Password do
  @moduledoc """
  Functions for dealing with refresh token strategy.
  """
  alias ExOauth2Provider.{
    AccessTokens,
    Config,
    Scopes,
    Token.Utils,
    Token.Utils.Response,
    Utils.Error}

  @doc """
  Will grant access token by password authentication.

  ## Example
      ExOauth2Provider.Token.grant(%{
        "grant_type" => "password",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "username" => "testuser@example.com",
        "password" => "secret"
      }, otp_app: :my_app)

  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map(), keyword()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "password"} = request, config \\ []) do
    {:ok, %{request: request}}
    |> get_password_auth_method(config)
    |> load_resource_owner()
    |> Utils.load_client(config)
    |> set_defaults()
    |> validate_scopes(config)
    |> issue_access_token(config)
    |> Response.response(config)
  end

  defp get_password_auth_method({:ok, params}, config) do
    case Config.password_auth(config) do
      {module, method} -> {:ok, Map.put(params, :password_auth, {module, method})}
      _                -> Error.add_error({:ok, params}, Error.unsupported_grant_type())
    end
  end

  defp load_resource_owner({:error, params}), do: {:error, params}
  defp load_resource_owner({:ok, %{password_auth: {module, method}, request: %{"username" => username, "password" => password}} = params}) do
    case apply(module, method, [username, password]) do
      {:ok, resource_owner} ->
        {:ok, Map.put(params, :resource_owner, resource_owner)}

      {:error, reason} ->
        {:error, Map.merge(params, %{error: :unauthorized, error_description: reason, error_http_status: :unauthorized})}
    end
  end
  defp load_resource_owner({:ok, params}), do: Error.add_error({:ok, params}, Error.invalid_request())

  defp issue_access_token({:error, params}, _config), do: {:error, params}
  defp issue_access_token({:ok, %{client: application, resource_owner: resource_owner, request: request} = params}, config) do
    scopes = request["scope"]
    token_params = %{use_refresh_token: Config.use_refresh_token?(config), scopes: scopes, application: application}

    resource_owner
    |> AccessTokens.get_token_for(application, scopes, config)
    |> case do
      nil          -> AccessTokens.create_token(resource_owner, token_params, config)
      access_token -> {:ok, access_token}
    end
    |> case do
      {:ok, access_token} -> {:ok, Map.merge(params, %{access_token: access_token})}
      {:error, error}     -> Error.add_error({:ok, params}, error)
    end
  end

  defp set_defaults({:error, params}), do: {:error, params}
  defp set_defaults({:ok, %{request: request, client: client} = params}) do
    scopes  = Map.get(params.request, "scope", client.scopes)
    request = Map.put(request, "scope", scopes)

    {:ok, Map.put(params, :request, request)}
  end

  defp validate_scopes({:error, params}, _config), do: {:error, params}
  defp validate_scopes({:ok, %{request: %{"scope" => scopes}, client: client} = params}, config) do
    scopes        = Scopes.to_list(scopes)
    server_scopes =
      client.scopes
      |> Scopes.to_list()
      |> Scopes.default_to_server_scopes(config)

    case Scopes.all?(server_scopes, scopes) do
      true -> {:ok, params}
      false -> Error.add_error({:ok, params}, Error.invalid_scopes())
    end
  end
end
