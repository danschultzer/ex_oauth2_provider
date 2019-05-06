defmodule ExOauth2Provider do
  @moduledoc """
  A module that provides OAuth 2 capabilities for Elixir applications.

  ## Configuration
      config :ex_oauth2_provider, ExOauth2Provider,
        repo: App.Repo,
        resource_owner: App.Users.User,
        application_owner: App.Users.User,
        default_scopes: ~w(public),
        optional_scopes: ~w(write update),
        native_redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
        authorization_code_expires_in: 600,
        access_token_expires_in: 7200,
        use_refresh_token: false,
        revoke_refresh_token_on_use: false,
        force_ssl_in_redirect_uri: true,
        grant_flows: ~w(authorization_code client_credentials),
        password_auth: nil,
        access_token_response_body_handler: nil

  If `revoke_refresh_token_on_use` is set to true,
  refresh tokens will be revoked after a related access token is used.

  If `revoke_refresh_token_on_use` is not set to true,
  previous tokens are revoked as soon as a new access token is created.

  If `use_refresh_token` is set to true, the refresh_token grant flow
  is automatically enabled.

  If `password_auth` is set to a {module, method} tuple, the password
  grant flow is automatically enabled.

  If access_token_expires_in is set to nil, access tokens will never
  expire.
  """

  alias ExOauth2Provider.{Config, AccessTokens}

  @doc """
  Authenticate an access token.

  ## Example

      ExOauth2Provider.authenticate_token("Jf5rM8hQBc")

  ## Response

      {:ok, access_token}
      {:error, reason}
  """
  @spec authenticate_token(binary()) :: {:ok, map()} | {:error, any()}
  def authenticate_token(nil), do: {:error, :token_inaccessible}
  def authenticate_token(token) do
    token
    |> load_access_token()
    |> maybe_revoke_previous_refresh_token()
    |> validate_access_token()
    |> load_resource()
  end

  defp load_access_token(token) do
    case AccessTokens.get_by_token(token) do
      nil          -> {:error, :token_not_found}
      access_token -> {:ok, access_token}
    end
  end

  defp maybe_revoke_previous_refresh_token({:error, error}), do: {:error, error}
  defp maybe_revoke_previous_refresh_token({:ok, access_token}) do
    case Config.refresh_token_revoked_on_use?() do
      true  -> revoke_previous_refresh_token(access_token)
      false -> {:ok, access_token}
    end
  end

  defp revoke_previous_refresh_token(access_token) do
    case AccessTokens.revoke_previous_refresh_token(access_token) do
      {:error, _any}       -> {:error, :no_association_found}
      {:ok, _access_token} -> {:ok, access_token}
    end
  end

  defp validate_access_token({:error, error}), do: {:error, error}
  defp validate_access_token({:ok, access_token}) do
    case AccessTokens.is_accessible?(access_token) do
      true  -> {:ok, access_token}
      false -> {:error, :token_inaccessible}
    end
  end

  defp load_resource({:error, error}), do: {:error, error}
  defp load_resource({:ok, access_token}) do
    access_token = repo().preload(access_token, :resource_owner)

    case has_association?(access_token) do
      true  -> {:ok, access_token}
      false -> {:error, :no_association_found}
    end
  end

  defp has_association?(access_token) do
    is_nil(access_token.resource_owner_id) || not is_nil(access_token.resource_owner)
  end

  @doc false
  @spec repo() :: Ecto.Repo.t()
  def repo, do: Keyword.get(Config.config(), :repo)
end
