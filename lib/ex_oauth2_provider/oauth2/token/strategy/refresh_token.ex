defmodule ExOauth2Provider.Token.RefreshToken do
  @moduledoc """
  Functions for dealing with refresh token strategy.
  """

  alias ExOauth2Provider.{Config,
                          Utils.Error,
                          Token.Utils,
                          Token.Utils.Response,
                          OauthAccessTokens,
                          OauthAccessTokens.OauthAccessToken}

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
  @spec grant(map()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "refresh_token"} = request) do
    %{request: request}
    |> Utils.load_client()
    |> load_access_token_by_refresh_token()
    |> issue_access_token_by_refresh_token()
    |> Response.response()
  end

  defp load_access_token_by_refresh_token(%{client: client, request: %{"refresh_token" => refresh_token}} = params) do
    access_token = client
                   |> OauthAccessTokens.get_by_refresh_token_for(refresh_token)
                   |> ExOauth2Provider.repo.preload(:resource_owner)
                   |> ExOauth2Provider.repo.preload(:application)

    case access_token do
      nil          -> Error.add_error(params, Error.invalid_request())
      access_token -> Map.put(params, :refresh_token, access_token)
    end
  end
  defp load_access_token_by_refresh_token(params), do: Error.add_error(params, Error.invalid_request())

  defp issue_access_token_by_refresh_token(%{error: _} = params), do: params
  defp issue_access_token_by_refresh_token(%{refresh_token: refresh_token, request: _} = params) do
    result = ExOauth2Provider.repo.transaction(fn ->
      token_params = %{application: refresh_token.application,
                       scopes: refresh_token.scopes,
                       expires_in: Config.access_token_expires_in,
                       use_refresh_token: true}
                     |> add_previous_refresh_token(refresh_token)

      refresh_token
      |> revoke_access_token()
      |> create_access_token(token_params)
    end)

    case result do
      {:ok, {:error, error}}     -> Error.add_error(params, error)
      {:ok, {:ok, access_token}} -> Map.merge(params, %{access_token: access_token})
      {:error, error}            -> Error.add_error(params, error)
    end
  end

  defp add_previous_refresh_token(params, refresh_token) do
    case Config.refresh_token_revoked_on_use? do
      true  -> Map.put(params, :previous_refresh_token, refresh_token)
      false -> params
    end
  end

  defp revoke_access_token(%OauthAccessToken{} = refresh_token) do
    cond do
      not Config.refresh_token_revoked_on_use? ->
        {:ok, refresh_token}

      OauthAccessTokens.is_revoked?(refresh_token) ->
        {:error, Error.invalid_request()}

      true ->
        OauthAccessTokens.revoke(refresh_token)
    end
  end

  defp create_access_token({:error, _} = error, _), do: error
  defp create_access_token({:ok, %OauthAccessToken{} = access_token}, token_params) do
    OauthAccessTokens.create_token(access_token.resource_owner, token_params)
  end
end
