defmodule ExOauth2Provider.Config do
  @moduledoc false

  @doc false
  @spec config() :: keyword()
  def config do
    app = otp_app()

    app
    |> Application.get_env(ExOauth2Provider)
    |> Kernel.||(Application.get_env(app, PhoenixOauth2Provider))
    |> Kernel.||(Application.get_env(:ex_oauth2_provider, PhoenixOauth2Provider))
    |> Kernel.||(Application.get_env(:phoenix_oauth2_provider, ExOAuth2Provider))
    |> Kernel.||([])
  end

  @doc false
  @spec resource_owner() :: atom()
  def resource_owner() do
    config()
    |> Keyword.get(:resource_owner)
    |> Kernel.||(app_module("Users", "User"))
  end

  defp app_module(context, module) do
    Module.concat([app_base(otp_app()), context, module])
  end

  @doc false
  @spec access_grant() :: atom()
  def access_grant(), do: get_oauth_struct(:access_grant)

  @doc false
  @spec access_token() :: atom()
  def access_token(), do: get_oauth_struct(:access_token)

  @doc false
  @spec application() :: atom()
  def application(), do: get_oauth_struct(:application)

  defp get_oauth_struct(name, namespace \\ "oauth") do
    context = Macro.camelize("#{namespace}_#{name}s")
    module  = Macro.camelize("#{namespace}_#{name}")

    config()
    |> Keyword.get(name)
    |> Kernel.||(app_module(context, module))
  end

  @doc false
  @spec otp_app() :: atom()
  def otp_app(), do: Keyword.fetch!(Mix.Project.config(), :app)

  @doc """
  Fetches the context base module for the app.
  """
  @spec app_base(atom()) :: module()
  def app_base(app) do
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
end
