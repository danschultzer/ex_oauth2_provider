defmodule ExOauth2Provider.Token.AuthorizationCode do
  @moduledoc """
  Functions for dealing with authorization code strategy.
  """
  alias ExOauth2Provider.OauthAccessGrants
  alias ExOauth2Provider.Token.Utils
  alias ExOauth2Provider.Token.Utils.Response
  alias ExOauth2Provider.Utils.Error

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
  def grant(%{"grant_type" => "authorization_code"} = request) do
    %{request: request}
    |> Utils.load_client
    |> load_active_access_grant
    |> validate_request
    |> issue_access_token_by_grant
    |> Response.response
  end

  defp issue_access_token_by_grant(%{error: _} = params), do: params
  defp issue_access_token_by_grant(%{access_grant: access_grant, request: _} = params) do
    token_params = %{scopes: access_grant.scopes,
                     application: access_grant.application,
                     use_refresh_token: ExOauth2Provider.Config.use_refresh_token?}

    result = ExOauth2Provider.repo.transaction(fn ->
      access_grant
      |> revoke_grant()
      |> Utils.find_or_create_access_token(token_params)
    end)

    case result do
      {:ok, {:error, error}}    -> Error.add_error(params, error)
      {:ok, {:ok, access_token}} -> Map.merge(params, %{access_token: access_token})
      {:error, error}            -> Error.add_error(params, error)
    end
  end

  defp revoke_grant(%OauthAccessGrants.OauthAccessGrant{revoked_at: nil} = access_grant),
    do: OauthAccessGrants.revoke(access_grant)

  defp load_active_access_grant(%{client: client, request: %{"code" => code}} = params) do
    access_grant = client
      |> OauthAccessGrants.get_active_grant_for(code)
      |> ExOauth2Provider.repo.preload(:resource_owner)
      |> ExOauth2Provider.repo.preload(:application)

    case access_grant do
      nil          -> Error.add_error(params, Error.invalid_grant())
      access_grant -> Map.merge(params, %{access_grant: access_grant})
    end
  end
  defp load_active_access_grant(params), do: Error.add_error(params, Error.invalid_grant())

  defp validate_request(params), do: validate_redirect_uri(params)

  defp validate_redirect_uri(%{error: _} = params), do: params
  defp validate_redirect_uri(%{request: %{"redirect_uri" => redirect_uri}, access_grant: grant} = params) do
    case grant.redirect_uri == redirect_uri do
      true  -> params
      false -> Error.add_error(params, Error.invalid_grant())
    end
  end
  defp validate_redirect_uri(params), do: Error.add_error(params, Error.invalid_grant())
end
