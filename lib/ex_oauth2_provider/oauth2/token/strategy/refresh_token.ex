defmodule ExOauth2Provider.Token.RefreshToken do
  @moduledoc """
  Functions for dealing with refresh token strategy.
  """

  alias ExOauth2Provider.Utils.Error
  alias ExOauth2Provider.Token.Utils
  alias ExOauth2Provider.Token.Utils.Response
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessTokens.OauthAccessToken

  @doc """

  ## Example
      ExOauth2Provider.Token.authorize(%{
        "grant_type" => "refresh_token",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "refresh_token" => "1jf6a"
      })

  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: _}, http_status}
  """
  def grant(%{"grant_type" => "refresh_token"} = request, config \\ ExOauth2Provider.Config) do
    %{request: request}
    |> Utils.load_client
    |> load_access_token_by_refresh_token
    |> issue_access_token_by_refresh_token(config.refresh_token_revoked_on_use?)
    |> Response.response
  end

  defp load_access_token_by_refresh_token(%{client: client, request: %{"refresh_token" => refresh_token}} = params) do
    access_token = client
                   |> OauthAccessTokens.get_by_refresh_token_for(refresh_token)
                   |> ExOauth2Provider.repo.preload(:resource_owner)
                   |> ExOauth2Provider.repo.preload(:application)

    case access_token do
      nil          -> Error.add_error(params, Error.invalid_request())
      access_token -> Map.merge(params, %{refresh_token: access_token})
    end
  end
  defp load_access_token_by_refresh_token(params), do: Error.add_error(params, Error.invalid_request())

  defp issue_access_token_by_refresh_token(%{error: _} = params, _), do: params
  defp issue_access_token_by_refresh_token(%{refresh_token: refresh_token, request: _} = params, refresh_token_revoked_on_use?) do
    result = ExOauth2Provider.repo.transaction(fn ->
      token_params = %{application: refresh_token.application,
                       scopes: refresh_token.scopes,
                       expires_in: ExOauth2Provider.Config.access_token_expires_in,
                       use_refresh_token: true}
                     |> add_previous_refresh_token(refresh_token, refresh_token_revoked_on_use?)

      refresh_token
      |> revoke_access_token(refresh_token_revoked_on_use?)
      |> create_access_token(token_params)
    end)

    case result do
      {:ok, {:error} = error}    -> Error.add_error(params, error)
      {:ok, {:ok, access_token}} -> Map.merge(params, %{access_token: access_token})
      {:error, error}            -> Error.add_error(params, error)
    end
  end

  defp add_previous_refresh_token(params, _, false), do: params
  defp add_previous_refresh_token(params, refresh_token, true) do
    Map.merge(params, %{previous_refresh_token: refresh_token})
  end

  defp revoke_access_token(%OauthAccessToken{} = refresh_token, refresh_token_revoked_on_use?) do
    cond do
      not refresh_token_revoked_on_use?                -> {:ok, refresh_token}
      OauthAccessTokens.is_revoked?(refresh_token)     -> {:error, Error.invalid_request()}
      true                                             -> OauthAccessTokens.revoke(refresh_token)
    end
  end

  defp create_access_token({:error, _} = error, _), do: error
  defp create_access_token({:ok, %OauthAccessToken{} = access_token}, token_params) do
    OauthAccessTokens.create_token(access_token.resource_owner, token_params)
  end
end
