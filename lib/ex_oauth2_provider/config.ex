defmodule ExOauth2Provider.Config do
  @moduledoc false

  @spec repo(keyword()) :: module()
  def repo(config) do
    get(config, :repo) ||
      raise """
      No `:repo` found in ExOauth2Provider configuration.

      Please set up the repo in your configuration:

      config #{inspect(Keyword.get(config, :otp_app, :ex_oauth2_provider))}, ExOauth2Provider,
        repo: MyApp.Repo
      """
  end

  @spec resource_owner(keyword()) :: module()
  def resource_owner(config),
    do: get(config, :resource_owner) || app_module(config, "Users", "User")

  defp app_module(config, context, module) do
    app =
      config
      |> Keyword.get(:otp_app)
      |> Kernel.||(
        raise "No `:otp_app` found in provided configuration. Please pass `:otp_app` in configuration."
      )
      |> app_base()

    Module.concat([app, context, module])
  end

  @spec access_grant(keyword()) :: module()
  def access_grant(config),
    do: get_oauth_struct(config, :access_grant)

  @spec access_token(keyword()) :: module()
  def access_token(config),
    do: get_oauth_struct(config, :access_token)

  @spec application(keyword()) :: module()
  def application(config),
    do: get_oauth_struct(config, :application)

  @spec device_grant(keyword()) :: module()
  def device_grant(config),
    do: get_oauth_struct(config, :device_grant)

  defp get_oauth_struct(config, name, namespace \\ "oauth") do
    context = Macro.camelize("#{namespace}_#{name}s")
    module = Macro.camelize("#{namespace}_#{name}")

    config
    |> get(name)
    |> Kernel.||(app_module(config, context, module))
  end

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
  @spec default_scopes(keyword()) :: [binary()]
  def default_scopes(config),
    do: get(config, :default_scopes, [])

  # Combined scopes list for your provider
  @spec server_scopes(keyword()) :: [binary()]
  def server_scopes(config) do
    config
    |> default_scopes()
    |> Kernel.++(get(config, :optional_scopes, []))
  end

  @spec redirect_uri_match_fun(keyword()) :: function() | nil
  def redirect_uri_match_fun(config),
    do: get(config, :redirect_uri_match_fun)

  @spec native_redirect_uri(keyword()) :: binary()
  def native_redirect_uri(config),
    do: get(config, :native_redirect_uri, "urn:ietf:wg:oauth:2.0:oob")

  @spec authorization_code_expires_in(keyword()) :: integer()
  def authorization_code_expires_in(config),
    do: get(config, :authorization_code_expires_in, 600)

  @spec access_token_expires_in(keyword()) :: integer()
  def access_token_expires_in(config),
    do: get(config, :access_token_expires_in, 7200)

  # Issue access tokens with refresh token (disabled by default)
  @spec use_refresh_token?(keyword()) :: boolean()
  def use_refresh_token?(config),
    do: get(config, :use_refresh_token, false)

  # Password auth method to use. Disabled by default. When set, it'll enable
  # password auth strategy. Set config as:
  # `password_auth: {MyModule, :my_auth_method}`
  @spec password_auth(keyword()) :: {atom(), atom()} | nil
  def password_auth(config),
    do: get(config, :password_auth)

  @spec refresh_token_revoked_on_use?(keyword()) :: boolean()
  def refresh_token_revoked_on_use?(config),
    do: get(config, :revoke_refresh_token_on_use, false)

  # Forces the usage of the HTTPS protocol in non-native redirect uris
  # (enabled by default in non-development environments). OAuth2
  # delegates security in communication to the HTTPS protocol so it is
  # wise to keep this enabled.
  @spec force_ssl_in_redirect_uri?(keyword()) :: boolean()
  def force_ssl_in_redirect_uri?(config),
    do: get(config, :force_ssl_in_redirect_uri, unquote(Mix.env() != :dev))

  # Use a custom access token generator
  @spec access_token_generator(keyword()) :: {atom(), atom()} | nil
  def access_token_generator(config),
    do: get(config, :access_token_generator)

  @spec access_token_response_body_handler(keyword()) :: {atom(), atom()} | nil
  def access_token_response_body_handler(config),
    do: get(config, :access_token_response_body_handler)

  @spec grant_flows(keyword()) :: [binary()]
  def grant_flows(config) do
    flows = get(config, :grant_flows, ~w(authorization_code client_credentials))

    case Enum.member?(flows, "device_code") do
      # Device flow requires grant type to be this for the token request.
      # Adding it in bound to the device code token strategy allows this to work
      # but also allows the configuration to only need "device_code" to enable.
      # https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
      true -> Enum.concat(flows, ["urn:ietf:params:oauth:grant-type:device_code"])
      false -> flows
    end
  end

  @spec device_flow_device_code_length(keyword()) :: non_neg_integer()
  def device_flow_device_code_length(config),
    do: config |> get(:device_flow_device_code_length, 32) |> abs()

  @spec device_flow_polling_interval(keyword()) :: non_neg_integer()
  def device_flow_polling_interval(config),
    do: config |> get(:device_flow_polling_interval, 5) |> abs()

  @spec device_flow_user_code_base(keyword()) :: non_neg_integer()
  def device_flow_user_code_base(config),
    do: config |> get(:device_flow_user_code_base, 36) |> abs()

  @spec device_flow_user_code_length(keyword()) :: non_neg_integer()
  def device_flow_user_code_length(config),
    do: config |> get(:device_flow_user_code_length, 8) |> abs()

  @spec device_flow_verification_uri(keyword()) :: binary()
  def device_flow_verification_uri(config),
    do:
      get(config, :device_flow_verification_uri) ||
        raise("""
        `:device_flow_verification_uri` is required to support the device flow.

        Please update your configuration with the uri your application uses to verify devices:

        config #{inspect(Keyword.get(config, :otp_app, :ex_oauth2_provider))}, ExOauth2Provider,
          device_flow_verification_uri: "https://really.cool.site/device"
        """)

  @doc """
  This returns the function to use to determine if we should skip authorization
  and automatically grant an authorization token. This is disabled by default.

  To implement it you can set :skip_authorization in the config to any function
  you wish to use to determine if it applies to the given user and/or application.

  The behavior ExOauth2Provider.Behaviors.SkipAuthorization is provided to help
  facilitate proper implementation.

  For example:

    config :my_app, ExOauth2Provider,
      skip_authorization_with: &MyModule.my_function/2


  Then you can do whatever you want with your implementation!

    defmodule MyModule do
      @behaviour ExOauth2Provider.Behaviors.SkipAuthorization

      def skip_authorization(user, application) do
        user.super_cool? || application.trusted?
      end
    end
  """
  @spec skip_authorization(keyword()) :: function()
  def skip_authorization(config) do
    get(
      config,
      :skip_authorization_with,
      &ExOauth2Provider.Features.skip_authorization?/2
    )
  end

  @doc """
  Returns a function that is used to verify that a token string is valid.
  This allows you to add in additional functionality like a caching layer or
  side effects.
  """
  def token_authenticator(config) do
    get(
      config,
      :authenticate_token_with,
      &ExOauth2Provider.authenticate_token/2
    )
  end

  defp get(config, key, value \\ nil) do
    otp_app = Keyword.get(config, :otp_app)

    config
    |> get_from_config(key)
    |> get_from_app_env(otp_app, key)
    |> get_from_global_env(key)
    |> case do
      :not_found -> value
      value -> value
    end
  end

  defp get_from_config(config, key), do: Keyword.get(config, key, :not_found)

  defp get_from_app_env(:not_found, nil, _key), do: :not_found

  defp get_from_app_env(:not_found, otp_app, key) do
    otp_app
    |> Application.get_env(ExOauth2Provider, [])
    |> Keyword.get(key, :not_found)
  end

  defp get_from_app_env(value, _otp_app, _key), do: value

  defp get_from_global_env(:not_found, key) do
    :ex_oauth2_provider
    |> Application.get_env(ExOauth2Provider, [])
    |> Keyword.get(key, :not_found)
  end

  defp get_from_global_env(value, _key), do: value
end
