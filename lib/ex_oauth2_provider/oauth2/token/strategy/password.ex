defmodule ExOauth2Provider.Token.Password do
  @moduledoc """
  Functions for dealing with refresh token strategy.
  """
  alias ExOauth2Provider.{Config,
                          Utils.Error,
                          Token.Utils,
                          Token.Utils.Response,
                          Scopes,
                          OauthAccessTokens}

  @doc """
  Will grant access token by password authentication.

  ## Example
      ExOauth2Provider.Token.grant(%{
        "grant_type" => "password",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "username" => "testuser@example.com",
        "password" => "secret"
      })
  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "password"} = request) do
    %{request: request}
    |> get_password_auth_method(Config.password_auth)
    |> load_resource_owner()
    |> Utils.load_client()
    |> set_defaults()
    |> validate_request()
    |> issue_access_token()
    |> Response.response()
  end

  defp get_password_auth_method(params, {module, method}) do
    Map.put(params, :password_auth, {module, method})
  end
  defp get_password_auth_method(params, _) do
    Error.add_error(params, Error.unsupported_grant_type())
  end

  defp load_resource_owner(%{error: _} = params), do: params
  defp load_resource_owner(%{password_auth: {module, method}, request: %{"username" => username, "password" => password}} = params) do
    case apply(module, method, [username, password]) do
      {:ok, resource_owner} ->
        Map.put(params, :resource_owner, resource_owner)

      {:error, reason} ->
        Map.merge(params, %{error: :unauthorized, error_description: reason, error_http_status: :unauthorized})
    end
  end
  defp load_resource_owner(params), do: Error.add_error(params, Error.invalid_request())

  defp issue_access_token(%{error: _} = params), do: params
  defp issue_access_token(%{client: client, resource_owner: resource_owner, request: request} = params) do
    token_params = %{use_refresh_token: Config.use_refresh_token?()}

    case OauthAccessTokens.get_or_create_token(resource_owner, client, request["scope"], token_params) do
      {:ok, access_token} -> Map.merge(params, %{access_token: access_token})
      {:error, error}     -> Error.add_error(params, error)
    end
  end

  defp set_defaults(%{error: _} = params), do: params
  defp set_defaults(%{request: request, client: client} = params) do
    scopes = Map.get(params.request, "scope", client.scopes)
    request = Map.put(request, "scope", scopes)

    Map.put(params, :request, request)
  end

  defp validate_request(params), do: validate_scopes(params)

  defp validate_scopes(%{error: _} = params), do: params
  defp validate_scopes(%{request: %{"scope" => scopes}, client: client} = params) do
    scopes = Scopes.to_list(scopes)
    server_scopes = client.scopes |> Scopes.to_list() |> Scopes.default_to_server_scopes()

    case Scopes.all?(server_scopes, scopes) do
      true -> params
      false -> Error.add_error(params, Error.invalid_scopes())
    end
  end
end
