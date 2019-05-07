defmodule ExOauth2Provider.Token.RefreshToken do
  @moduledoc """
  Functions for dealing with refresh token strategy.
  """

  alias ExOauth2Provider.{
    AccessTokens,
    Config,
    Token.Utils,
    Token.Utils.Response,
    Utils.Error}

  @doc """
  Will grant access token by refresh token.

  ## Example
      ExOauth2Provider.Token.authorize(%{
        "grant_type" => "refresh_token",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "refresh_token" => "1jf6a"
      })

  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map(), keyword()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "refresh_token"} = request, config \\ []) do
    {:ok, %{request: request}}
    |> Utils.load_client(config)
    |> load_access_token_by_refresh_token(config)
    |> issue_access_token_by_refresh_token(config)
    |> Response.response(config)
  end

  defp load_access_token_by_refresh_token({:ok, %{client: client, request: %{"refresh_token" => refresh_token}} = params}, config) do
    access_token =
      client
      |> AccessTokens.get_by_refresh_token_for(refresh_token, config)
      |> Config.repo(config).preload(:resource_owner)
      |> Config.repo(config).preload(:application)

    case access_token do
      nil          -> Error.add_error({:ok, params}, Error.invalid_request())
      access_token -> {:ok, Map.put(params, :refresh_token, access_token)}
    end
  end
  defp load_access_token_by_refresh_token(params, _config), do: Error.add_error(params, Error.invalid_request())

  defp issue_access_token_by_refresh_token({:error, params}, _config), do: {:error, params}
  defp issue_access_token_by_refresh_token({:ok, %{refresh_token: refresh_token, request: _} = params}, config) do
    result = Config.repo(config).transaction(fn ->
      token_params = token_params(refresh_token, config)

      refresh_token
      |> revoke_access_token(config)
      |> case do
        {:ok, %{resource_owner: resource_owner}} -> AccessTokens.create_token(resource_owner, token_params, config)
        {:error, error}     -> {:error, error}
      end
    end)

    case result do
      {:ok, {:error, error}}     -> Error.add_error({:ok, params}, error)
      {:ok, {:ok, access_token}} -> {:ok, Map.merge(params, %{access_token: access_token})}
      {:error, error}            -> Error.add_error({:ok, params}, error)
    end
  end

  defp token_params(%{scopes: scopes, application: application} = refresh_token, config) do
    params = %{scopes: scopes, application: application, use_refresh_token: true}

    case Config.refresh_token_revoked_on_use?(config) do
      true  -> Map.put(params, :previous_refresh_token, refresh_token)
      false -> params
    end
  end

  defp revoke_access_token(refresh_token, config) do
    cond do
      not Config.refresh_token_revoked_on_use?(config) ->
        {:ok, refresh_token}

      AccessTokens.is_revoked?(refresh_token) ->
        {:error, Error.invalid_request()}

      true ->
        AccessTokens.revoke(refresh_token, config)
    end
  end
end
