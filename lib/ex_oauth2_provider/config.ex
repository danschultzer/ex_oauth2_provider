defmodule ExOauth2Provider.Config do
  @moduledoc false

  defp config() do
    ExOauth2Provider.config()
  end

  @doc false
  def resource_owner_struct do
    Keyword.get(config(), :resource_owner)
  end

  @doc false
  def application_owner_struct do
    Keyword.get(config(), :application_owner, resource_owner_struct())
  end

  # Define default access token scopes for your provider
  @doc false
  def default_scopes do
    Keyword.get(config(), :default_scopes, [])
  end

  # Define optional access token scopes for your provider
  @doc false
  defp optional_scopes do
    Keyword.get(config(), :optional_scopes, [])
  end

  # Combined scopes list for your provider
  @doc false
  def server_scopes do
    default_scopes() ++ optional_scopes()
  end

  @doc false
  def native_redirect_uri do
     Keyword.get(config(), :native_redirect_uri, "urn:ietf:wg:oauth:2.0:oob")
  end

  @doc false
  def authorization_code_expires_in do
    Keyword.get(config(), :authorization_code_expires_in, 600)
  end

  @doc false
  def access_token_expires_in do
    Keyword.get(config(), :access_token_expires_in, 7200)
  end

  # Issue access tokens with refresh token (disabled by default)
  @doc false
  def use_refresh_token? do
    Keyword.get(config(), :use_refresh_token, false)
  end

  # Password auth method to use. Disabled by default. When set, it'll enable
  # password auth strategy. Set config as:
  # `password_auth: {MyModule, :my_auth_method}`
  @doc false
  def password_auth do
    Keyword.get(config(), :password_auth, nil)
  end

  @doc false
  def refresh_token_revoked_on_use? do
    Keyword.get(config(), :revoke_refresh_token_on_use, false)
  end

  # Forces the usage of the HTTPS protocol in non-native redirect uris
  # (enabled by default in non-development environments). OAuth2
  # delegates security in communication to the HTTPS protocol so it is
  # wise to keep this enabled.
  @doc false
  def force_ssl_in_redirect_uri? do
    Keyword.get(config(), :force_ssl_in_redirect_uri, Mix.env != :dev)
  end

  # Use a custom access token generator
  @doc false
  def access_token_generator do
    Keyword.get(config(), :access_token_generator, nil)
  end

  def access_token_response_body_handler do
    Keyword.get(config(), :access_token_response_body_handler, nil)
  end

  @doc false
  def grant_flows do
    Keyword.get(config(), :grant_flows, ~w(authorization_code client_credentials))
  end

  @doc false
  def calculate_authorization_response_types do
    %{"authorization_code" => {:code, ExOauth2Provider.Authorization.Code}}
    |> Enum.filter(fn({k, _}) -> Enum.member?(grant_flows(), k) end)
    |> Enum.map(fn({_, v}) -> v end)
  end

  @doc false
  def calculate_token_grant_types do
    [authorization_code: ExOauth2Provider.Token.AuthorizationCode,
     client_credentials: ExOauth2Provider.Token.ClientCredentials,
     password: ExOauth2Provider.Token.Password,
     refresh_token: ExOauth2Provider.Token.RefreshToken]
    |> Enum.filter(fn({k, _}) -> grant_type_can_be_used?(grant_flows(), to_string(k)) end)
  end

  defp grant_type_can_be_used?(_, "refresh_token"),
    do: use_refresh_token?()
  defp grant_type_can_be_used?(_, "password"),
    do: not is_nil(password_auth())
  defp grant_type_can_be_used?(grant_flows, grant_type) do
    Enum.member?(grant_flows, grant_type)
  end
end
