defmodule ExOauth2Provider.Token.Introspect do
  @moduledoc """
  Functions for dealing with token introspection.
  """
  alias ExOauth2Provider.{
    AccessTokens,
    Utils.Error,
    Token.Utils,
    Token.Utils.Response,
    Mixin.Expirable,
    Mixin.Revocable,
    Config,
    Schema
  }

  # 'token_type_hint' query param is not needed to guess if the token is an access or refresh token and can be safely ignored: https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
  def introspect(%{"token" => _} = request, config \\ []) do
    {:ok, %{request: request}}
    |> Utils.load_client(config)
    |> check_access_token(config)
    |> check_refresh_token(config)
    |> build_response(config)
  end

  def introspect(_, _), do: Error.invalid_request()

  defp check_access_token({:ok, %{client: client, request: %{"token" => token}} = params}, config) do
    access_token = AccessTokens.get_by_token_for(client, token, config)

    params =
      if access_token == nil || Expirable.is_expired?(access_token) ||
           Revocable.is_revoked?(access_token) do
        Map.merge(params, %{active: false})
      else
        Map.merge(params, %{active: true, token: access_token, type: :access_token})
      end

    {:ok, params}
  end

  defp check_access_token({:error, _} = req, _config), do: req

  defp check_refresh_token({:ok, %{client: client, active: false, request: %{"token" => token}} = params}, config) do
    refresh_token = AccessTokens.get_by_refresh_token_for(client, token, config)

    params =
      if refresh_token == nil || Revocable.is_revoked?(refresh_token) do
        Map.merge(params, %{active: false})
      else
        Map.merge(params, %{active: true, token: refresh_token, type: :refresh_token})
      end

    {:ok, params}
  end

  defp check_refresh_token({:ok, %{active: true}} = req, _config), do: req
  defp check_refresh_token({:error, _} = req, _config), do: req

  defp build_response({:ok, %{active: true, token: token, type: token_type}}, config) do
    token = Config.repo(config).preload(token, :application)

    created_at = Schema.unix_time_for(token.inserted_at)
    expires_at =
      if token_type == :access_token do
        created_at + token.expires_in
      else # refresh tokens don't expire
        nil
      end

    # as defined in https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
    {:ok,
     %{
       active: true,
       scope: token.scopes,
       token_type: "bearer",
       client_id: token.application.uid,
       iat: created_at,
       exp: expires_at
     }}
  end

  defp build_response({:ok, %{active: false}}, _), do: {:ok, %{active: false}}
  defp build_response({:error, _} = params, config), do: Response.response(params, config)
end
