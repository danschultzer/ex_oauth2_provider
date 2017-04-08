defmodule ExOauth2Provider do
  @moduledoc """
  A module that provides OAuth 2 based server for Elixir applications.

  ## Configuration
      config :ex_oauth2_provider, ExOauth2Provider,
        repo: App.Repo,
        resource_owner: App.User,
        default_scopes: ~w(public),
        optional_scopes: ~w(write update),
        native_redirect_uri: "urn:ietf:wg:oauth:2.0:oob",
        authorization_code_expires_in: 600,
        access_token_expires_in: 7200,
        use_refresh_token: false,
        revoke_refresh_token_on_use: false

  If `revoke_refresh_token_on_use` is set to true,
  refresh tokens will be revoked after a related access token is used.

  If `revoke_refresh_token_on_use` is not set to true,
  previous tokens are revoked as soon as a new access token is created.
  """

  @config                        Application.get_env(:ex_oauth2_provider, ExOauth2Provider, Application.get_env(:phoenix_oauth2_provider, PhoenixOauth2Provider, []))

  @repo                          Keyword.get(@config, :repo)
  @resource_owner_struct         Keyword.get(@config, :resource_owner)
  @default_scopes                Keyword.get(@config, :default_scopes, [])
  @optional_scopes               Keyword.get(@config, :optional_scopes, [])
  @server_scopes                 @default_scopes ++ @optional_scopes
  @native_redirect_uri           Keyword.get(@config, :native_redirect_uri, "urn:ietf:wg:oauth:2.0:oob")
  @authorization_code_expires_in Keyword.get(@config, :authorization_code_expires_in, 600)
  @access_token_expires_in       Keyword.get(@config, :access_token_expires_in, 7200)
  @use_refresh_token             Keyword.get(@config, :use_refresh_token, false)
  @password_auth                 Keyword.get(@config, :password_auth, nil)
  @refresh_token_revoked_on_use  Keyword.get(@config, :revoke_refresh_token_on_use, false)

  @doc """
  Authenticate the token.
  """
  @spec authenticate_token(String.t) :: {:ok, map} |
                                        {:error, any}
  def authenticate_token(nil), do: {:error, :token_inaccessible}
  def authenticate_token(token, refresh_token_revoked_on_use? \\ ExOauth2Provider.refresh_token_revoked_on_use?) do
    token
    |> load_access_token
    |> revoke_previous_refresh_token(refresh_token_revoked_on_use?)
    |> validate_access_token
    |> load_resource
  end

  defp load_access_token(token) do
    case ExOauth2Provider.OauthAccessTokens.get_by_token(token) do
      nil          -> {:error, :token_not_found}
      access_token -> {:ok, access_token}
    end
  end

  defp validate_access_token({:error, _} = error), do: error
  defp validate_access_token({:ok, access_token}) do
    case ExOauth2Provider.OauthAccessTokens.is_accessible?(access_token) do
      true -> {:ok, access_token}
      _    -> {:error, :token_inaccessible}
    end
  end

  defp load_resource({:error, _} = error), do: error
  defp load_resource({:ok, access_token}) do
    access_token = @repo.preload(access_token, :resource_owner)

    case access_token.resource_owner do
      nil -> {:error, :no_association_found}
      _   -> {:ok, access_token}
    end
  end

  defp revoke_previous_refresh_token({:error, _} = error, _), do: error
  defp revoke_previous_refresh_token({:ok, _} = params, false), do: params
  defp revoke_previous_refresh_token({:ok, access_token}, true) do
    case ExOauth2Provider.OauthAccessTokens.revoke_previous_refresh_token(access_token) do
      nil -> {:error, :no_association_found}
      _   -> {:ok, access_token}
    end
  end

  def resource_owner_struct, do: @resource_owner_struct
  def repo, do: @repo
  def default_scopes, do: @default_scopes
  def server_scopes, do: @server_scopes
  def native_redirect_uri, do: @native_redirect_uri
  def authorization_code_expires_in, do: @authorization_code_expires_in
  def access_token_expires_in, do: @access_token_expires_in
  def use_refresh_token?, do: @use_refresh_token
  def password_auth, do: @password_auth
  def refresh_token_revoked_on_use?, do: @refresh_token_revoked_on_use
end
