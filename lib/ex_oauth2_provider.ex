defmodule ExOauth2Provider do
  @moduledoc """
  A module that provides OAuth 2 capabilities for Elixir applications.

  ## Configuration
      config :my_app, ExOauth2Provider,
        repo: App.Repo,
        resource_owner: App.Users.User,
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

      ExOauth2Provider.authenticate_token("Jf5rM8hQBc", otp_app: :my_app)

  ## Response

      {:ok, access_token}
      {:error, reason}
  """
  @spec authenticate_token(binary(), keyword()) :: {:ok, map()} | {:error, any()}
  def authenticate_token(token, config \\ [])
  def authenticate_token(nil, _config), do: {:error, :token_inaccessible}
  def authenticate_token(token, config) do
    token
    |> load_access_token(config)
    |> maybe_revoke_previous_refresh_token(config)
    |> validate_access_token()
    |> load_resource_owner(config)
  end

  defp load_access_token(token, config) do
    case AccessTokens.get_by_token(token, config) do
      nil          -> {:error, :token_not_found}
      access_token -> {:ok, access_token}
    end
  end

  defp maybe_revoke_previous_refresh_token({:error, error}, _config), do: {:error, error}
  defp maybe_revoke_previous_refresh_token({:ok, access_token}, config) do
    case Config.refresh_token_revoked_on_use?(config) do
      true  -> revoke_previous_refresh_token(access_token, config)
      false -> {:ok, access_token}
    end
  end

  defp revoke_previous_refresh_token(access_token, config) do
    case AccessTokens.revoke_previous_refresh_token(access_token, config) do
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

  defp load_resource_owner({:error, error}, _config), do: {:error, error}
  defp load_resource_owner({:ok, access_token}, config) do
    repo         = Config.repo(config)
    access_token = repo.preload(access_token, :resource_owner)

    {:ok, access_token}
  end
end
