defmodule ExOauth2Provider.Config do
  @moduledoc false

  @doc false
  @spec config() :: keyword()
  def config do
    Application.get_env(:ex_oauth2_provider, ExOauth2Provider, Application.get_env(:phoenix_oauth2_provider, PhoenixOauth2Provider, []))
  end

  @doc false
  @spec resource_owner_struct(atom()) :: atom()
  def resource_owner_struct(type) do
    config()
    |> Keyword.get(:resource_owner)
    |> parse_owner_struct(type)
  end

  @doc false
  @spec access_grant() :: atom()
  def access_grant() do
    config()
    |> Keyword.get(:access_grant)
    |> Kernel.||(Module.concat([app_base(), "OauthAccessGants", "OauthAccessGant"]))
  end

  @doc false
  @spec access_token() :: atom()
  def access_token() do
    config()
    |> Keyword.get(:access_token)
    |> Kernel.||(Module.concat([app_base(), "OathAccessTokens", "OauthAccessToken"]))
  end

  @doc false
  @spec application() :: atom()
  def application() do
    config()
    |> Keyword.get(:application)
    |> Kernel.||(Module.concat([app_base(), "OauthApplications", "OauthApplication"]))
  end

  defp app_base() do
    app = Keyword.fetch!(Mix.Project.config(), :app)

    case Application.get_env(app, :namespace, app) do
      ^app ->
        app
        |> to_string()
        |> Macro.camelize()
        |> List.wrap()
        |> Module.concat()

      mod ->
        mod
    end
  end

  @doc false
  @spec app_schema() :: atom()
  def app_schema do
    Keyword.get(config(), :app_schema, Ecto.Schema)
  end

  @doc false
  @spec application_owner_struct(atom()) :: atom()
  def application_owner_struct(type) do
    resource_owner = Keyword.get(config(), :resource_owner)

    config()
    |> Keyword.get(:application_owner, resource_owner)
    |> parse_owner_struct(type)
  end

  # Define default access token scopes for your provider
  @doc false
  @spec default_scopes() :: [binary()]
  def default_scopes do
    Keyword.get(config(), :default_scopes, [])
  end

  # Define optional access token scopes for your provider
  @doc false
  @spec optional_scopes() :: [binary()]
  defp optional_scopes do
    Keyword.get(config(), :optional_scopes, [])
  end

  # Combined scopes list for your provider
  @doc false
  @spec server_scopes() :: [binary()]
  def server_scopes do
    default_scopes() ++ optional_scopes()
  end

  @doc false
  @spec native_redirect_uri() :: binary()
  def native_redirect_uri do
     Keyword.get(config(), :native_redirect_uri, "urn:ietf:wg:oauth:2.0:oob")
  end

  @doc false
  @spec authorization_code_expires_in() :: integer()
  def authorization_code_expires_in do
    Keyword.get(config(), :authorization_code_expires_in, 600)
  end

  @doc false
  @spec access_token_expires_in() :: integer()
  def access_token_expires_in do
    Keyword.get(config(), :access_token_expires_in, 7200)
  end

  # Issue access tokens with refresh token (disabled by default)
  @doc false
  @spec use_refresh_token?() :: boolean()
  def use_refresh_token? do
    Keyword.get(config(), :use_refresh_token, false)
  end

  # Password auth method to use. Disabled by default. When set, it'll enable
  # password auth strategy. Set config as:
  # `password_auth: {MyModule, :my_auth_method}`
  @doc false
  @spec password_auth() :: {atom(), atom()} | nil
  def password_auth do
    Keyword.get(config(), :password_auth, nil)
  end

  @doc false
  @spec refresh_token_revoked_on_use?() :: boolean()
  def refresh_token_revoked_on_use? do
    Keyword.get(config(), :revoke_refresh_token_on_use, false)
  end

  # Forces the usage of the HTTPS protocol in non-native redirect uris
  # (enabled by default in non-development environments). OAuth2
  # delegates security in communication to the HTTPS protocol so it is
  # wise to keep this enabled.
  @doc false
  @spec force_ssl_in_redirect_uri?() :: boolean()
  def force_ssl_in_redirect_uri? do
    Keyword.get(config(), :force_ssl_in_redirect_uri, Mix.env != :dev)
  end

  # Use a custom access token generator
  @doc false
  @spec access_token_generator() :: {atom(), atom()} | nil
  def access_token_generator do
    Keyword.get(config(), :access_token_generator, nil)
  end

  @doc false
  @spec access_token_response_body_handler() :: {atom(), atom()} | nil
  def access_token_response_body_handler do
    Keyword.get(config(), :access_token_response_body_handler, nil)
  end

  @doc false
  @spec grant_flows() :: [binary()]
  def grant_flows do
    Keyword.get(config(), :grant_flows, ~w(authorization_code client_credentials))
  end

  defp parse_owner_struct({_module, options}, :options) when is_list(options), do: options
  defp parse_owner_struct({_module, foreign_key_type}, :options), do: [type: foreign_key_type]
  defp parse_owner_struct({module, _options}, :module), do: module
  defp parse_owner_struct(module, :module), do: module
  defp parse_owner_struct(_module, :options), do: []
end
