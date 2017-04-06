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
        use_refresh_token: false
  """

  @config                        Application.get_env(:ex_oauth2_provider, ExOauth2Provider, [])
  @fallback_config               Application.get_env(:phoenix_oauth2_provider, PhoenixOauth2Provider, [])

  @repo                          Keyword.get(@config, :repo, Keyword.get(@fallback_config, :repo))
  @resource_owner_struct         Keyword.get(@config, :resource_owner, Keyword.get(@fallback_config, :resource_owner))
  @default_scopes                Keyword.get(@config, :default_scopes, Keyword.get(@fallback_config, :default_scopes, []))
  @optional_scopes               Keyword.get(@config, :optional_scopes, Keyword.get(@fallback_config, :optional_scopes, []))
  @server_scopes                 @default_scopes ++ @optional_scopes
  @native_redirect_uri           Keyword.get(@config, :native_redirect_uri, Keyword.get(@fallback_config, :native_redirect_uri, "urn:ietf:wg:oauth:2.0:oob"))
  @authorization_code_expires_in Keyword.get(@config, :authorization_code_expires_in, Keyword.get(@fallback_config, :authorization_code_expires_in, 600))
  @access_token_expires_in       Keyword.get(@config, :access_token_expires_in, Keyword.get(@fallback_config, :access_token_expires_in, 7200))
  @use_refresh_token             Keyword.get(@config, :use_refresh_token, Keyword.get(@fallback_config,  :use_refresh_token, false))

  if is_nil(@repo), do: raise "ExOauth2Provider requires a repo"
  if is_nil(@resource_owner_struct), do: raise "ExOauth2Provider requires a resource owner (e.g. User)"

  @doc """
  Authenticate the token.
  """
  @spec authenticate_token(String.t) :: {:ok, map} |
                                        {:error, any}
  def authenticate_token(nil), do: {:error, :token_inaccessible}
  def authenticate_token(token) do
    token
    |> load_access_token
    |> validate_access_token
    |> load_resource
  end

  defp load_access_token(token) do
    case ExOauth2Provider.OauthAccessTokens.get_token(token) do
      nil          -> {:error, :token_not_found}
      access_token -> {:ok, access_token}
    end
  end

  defp validate_access_token({:error, reason}), do: {:error, reason}
  defp validate_access_token({:ok, access_token}) do
    case ExOauth2Provider.OauthAccessTokens.is_accessible?(access_token) do
      true -> {:ok, access_token}
      _    -> {:error, :token_inaccessible}
    end
  end

  defp load_resource({:error, reason}), do: {:error, reason}
  defp load_resource({:ok, access_token}) do
    access_token = @repo.preload(access_token, :resource_owner)

    case access_token.resource_owner do
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
  def refresh_token_enabled, do: @use_refresh_token
end
