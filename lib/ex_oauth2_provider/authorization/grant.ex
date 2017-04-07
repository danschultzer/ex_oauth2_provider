defmodule ExOauth2Provider.Authorization.Grant do
  @moduledoc """
  Functions for dealing with authorization grant.
  """
  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessGrants

  @doc """
  Will attempt to authorize an access grant.
  ## Authorization Code Grant Example
    ExOauth2Provider.Authorization.Grant.authorize(%{
      "code" => "1jf6a",
      "client_id" => "Jf5rM8hQBc",
      "client_secret" => "secret",
      "redirect_uri" => "https://example.com/",
      "grant_type" => "authorization_code"
    })
  ## Response
    {:ok, access_token}
    {:error, %{error: error, error_description: _}, http_status}

  ## Client Credentials Grant Example
    resource_owner
    |> ExOauth2Provider.Authorization.Grant.authorize(%{
      "grant_type" => "client_credentials",
      "client_id" => "Jf5rM8hQBc",
      "client_secret" => "secret"
    })
  ## Response
    {:ok, access_token}
    {:error, %{error: error, error_description: _}, http_status}
  """
  def authorize(%{"grant_type" => "client_credentials"} = request) do
    %{request: request}
    |> load_client
    |> issue_access_token_by_creds
    |> authorize_response
  end
  def authorize(%{"grant_type" => "authorization_code"} = request) do
    %{request: request}
    |> load_client
    |> load_access_grant
    |> validate_redirect_uri
    |> issue_access_token_by_grant
    |> authorize_response
  end
  def authorize(%{"grant_type" => _}), do: unsupported_grant_type()
  def authorize(_), do: invalid_request()

  @doc false
  defp issue_access_token_by_creds(%{error: _} = params), do: params
  defp issue_access_token_by_creds(%{client: client} = params) do
    client = client
    |> ExOauth2Provider.repo.preload(:resource_owner)

    token_params = %{scopes: client.scopes,
                     application: client,
                     # client_credentials MUST NOT use refresh tokens
                     use_refresh_token: false}

    case create_access_token(client.resource_owner, token_params) do
      {:ok, access_token} -> Map.merge(params, %{access_token: access_token})
      {:error, error}     -> add_error(params, error)
    end
  end

  @doc false
  defp issue_access_token_by_grant(%{error: _} = params), do: params
  defp issue_access_token_by_grant(%{access_grant: access_grant, request: _} = params) do
    result = ExOauth2Provider.repo.transaction(fn ->
      access_grant
      |> revoke_grant
      |> create_access_token(%{scopes: access_grant.scopes,
                               application: access_grant.application})
    end)

    case result do
      {:ok, {:error} = error}    -> add_error(params, error)
      {:ok, {:ok, access_token}} -> Map.merge(params, %{access_token: access_token})
      {:error, error}            -> add_error(params, error)
    end
  end

  @doc false
  defp revoke_grant(%OauthAccessGrants.OauthAccessGrant{} = access_grant) do
    case OauthAccessGrants.is_revoked?(access_grant) do
      true -> invalid_grant()
      false -> OauthAccessGrants.revoke(access_grant)
    end
  end

  @doc false
  defp create_access_token({:error, _} = error, _), do: error
  defp create_access_token({:ok, access_grant}, token_params),
    do: create_access_token(access_grant.resource_owner, token_params)
  defp create_access_token(%{id: _} = resource_owner, token_params) do
    token_params = %{expires_in: ExOauth2Provider.access_token_expires_in,
                   use_refresh_token: ExOauth2Provider.refresh_token_enabled}
                   |> Map.merge(token_params)
    OauthAccessTokens.find_or_create_token(resource_owner, token_params)
  end

  @doc false
  defp authorize_response(%{access_token: token} = _) do
    build_response(%{access_token: token})
  end
  defp authorize_response(%{error: _} = params) do
    build_response(params)
  end

  @doc false
  defp load_client(%{request: %{"client_id" => client_id, "client_secret" => client_secret}} = params) do
    case OauthApplications.get_application(client_id, client_secret) do
      nil    -> add_error(params, invalid_client())
      client -> Map.merge(params, %{client: client})
    end
  end
  defp load_client(params), do: add_error(params, invalid_request())

  @doc false
  defp load_access_grant(%{client: client, request: %{"code" => code}} = params) do
    access_grant = client
      |> OauthAccessGrants.get_grant(code)
      |> ExOauth2Provider.repo.preload(:resource_owner)
      |> ExOauth2Provider.repo.preload(:application)

    case access_grant do
      nil          -> add_error(params, invalid_grant())
      access_grant -> Map.merge(params, %{access_grant: access_grant})
    end
  end
  defp load_access_grant(params), do: add_error(params, invalid_grant())

  @doc false
  defp validate_redirect_uri(%{error: _} = params), do: params
  defp validate_redirect_uri(%{request: %{"redirect_uri" => redirect_uri}, access_grant: grant} = params) do
    case grant.redirect_uri === redirect_uri do
      true  -> params
      false -> add_error(params, invalid_grant())
    end
  end
  defp validate_redirect_uri(params), do: add_error(params, invalid_grant())

  @doc false
  defp add_error(%{error: _} = params, _), do: params
  defp add_error(params, {:error, error, http_status}) do
    Map.merge(params, %{error: error, error_http_status: http_status})
  end

  @doc false
  defp invalid_request do
    msg = "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
    {:error, %{error: :invalid_request, error_description: msg}, :bad_request}
  end

  @doc false
  defp invalid_client do
    msg = "Client authentication failed due to unknown client, no client authentication included, or unsupported authentication method."
    {:error, %{error: :invalid_client, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  defp invalid_grant do
    msg = "The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client."
    {:error, %{error: :invalid_grant, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  defp unsupported_grant_type do
    msg = "The authorization grant type is not supported by the authorization server."
    {:error, %{error: :unsupported_grant_type, error_description: msg}, :unprocessable_entity}
  end

  @doc false
  defp build_response(%{access_token: access_token} = _) do
    {:ok, %{access_token: access_token.token,
            # Access Token type: Bearer.
            # @see https://tools.ietf.org/html/rfc6750
            #   The OAuth 2.0 Authorization Framework: Bearer Token Usage
            #
            token_type: "bearer",
            expires_in: access_token.expires_in,
            refresh_token: access_token.refresh_token,
            scope: access_token.scopes,
            created_at: access_token.inserted_at
          }}
  end
  defp build_response(%{error: error, error_http_status: error_http_status} = _) do
    {:error, error, error_http_status}
  end
  defp build_response(%{error: error}) do # For DB errors
    {:error, error, :bad_request}
  end
end
