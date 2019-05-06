defmodule ExOauth2Provider.Token.AuthorizationCode do
  @moduledoc """
  Functions for dealing with authorization code strategy.
  """
  alias ExOauth2Provider.{
    Config,
    AccessGrants,
    Token.Utils,
    Token.Utils.Response,
    Utils.Error,
    AccessTokens}

  @doc """
  Will grant access token by client credentials.

  ## Example
      ExOauth2Provider.Token.grant(%{
        "code" => "1jf6a",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "redirect_uri" => "https://example.com/",
        "grant_type" => "authorization_code"
      })

  ## Response
      {:ok, access_token}
      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map()) :: {:ok, map()} | {:error, map(), atom()}
  def grant(%{"grant_type" => "authorization_code"} = request) do
    {:ok, %{request: request}}
    |> Utils.load_client()
    |> load_active_access_grant()
    |> validate_redirect_uri()
    |> issue_access_token_by_grant()
    |> Response.response()
  end

  defp issue_access_token_by_grant({:error, params}), do: {:error, params}
  defp issue_access_token_by_grant({:ok, %{access_grant: access_grant, request: _} = params}) do
    token_params = %{use_refresh_token: Config.use_refresh_token?()}

    result = ExOauth2Provider.repo.transaction(fn ->
      access_grant
      |> revoke_grant()
      |> maybe_create_access_token(token_params)
    end)

    case result do
      {:ok, {:error, error}}     -> Error.add_error({:ok, params}, error)
      {:ok, {:ok, access_token}} -> {:ok, Map.put(params, :access_token, access_token)}
      {:error, error}            -> Error.add_error({:ok, params}, error)
    end
  end

  defp revoke_grant(%{revoked_at: nil} = access_grant),
    do: AccessGrants.revoke(access_grant)

  defp maybe_create_access_token({:error, _} = error, _token_params), do: error
  defp maybe_create_access_token({:ok, access_grant}, token_params),
    do: AccessTokens.get_or_create_token(access_grant.resource_owner, access_grant.application, access_grant.scopes, token_params)

  defp load_active_access_grant({:ok, %{client: client, request: %{"code" => code}} = params}) do
    client
    |> AccessGrants.get_active_grant_for(code)
    |> ExOauth2Provider.repo.preload(:resource_owner)
    |> ExOauth2Provider.repo.preload(:application)
    |> case do
      nil          -> Error.add_error({:ok, params}, Error.invalid_grant())
      access_grant -> {:ok, Map.put(params, :access_grant, access_grant)}
    end
  end
  defp load_active_access_grant({:ok, params}), do: Error.add_error({:ok, params}, Error.invalid_grant())
  defp load_active_access_grant({:error, error}), do: {:error, error}

  defp validate_redirect_uri({:error, params}), do: {:error, params}
  defp validate_redirect_uri({:ok, %{request: %{"redirect_uri" => redirect_uri}, access_grant: grant} = params}) do
    case grant.redirect_uri == redirect_uri do
      true  -> {:ok, params}
      false -> Error.add_error({:ok, params}, Error.invalid_grant())
    end
  end
  defp validate_redirect_uri({:ok, params}), do: Error.add_error({:ok, params}, Error.invalid_grant())
end
