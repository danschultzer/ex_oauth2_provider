defmodule ExOauth2Provider.Token.Introspect do
  @moduledoc """
  Functions for dealing with token introspection.
  """
  alias ExOauth2Provider.{
    AccessTokens,
    Utils.Error,
    Mixin.Expirable,
    Mixin.Revocable,
    Config
  }

  # 'token_type_hint' query param is not needed to guess if the token is an access or refresh token and can be safely ignored: https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
  def introspect(%{"token" => token}, config \\ []) do
    {:ok, %{token: token}}
    |> check_access_token(config)
    |> check_refresh_token(config)
    |> build_response(config)
  end

  def introspect(_, _), do: Error.invalid_request()

  defp check_access_token({:ok, %{token: token} = params}, config) do
    access_token = AccessTokens.get_by_token(token, config)

    if access_token == nil || Expirable.is_expired?(access_token) ||
         Revocable.is_revoked?(access_token) do
      {:ok, Map.merge(params, %{active: false})}
    else
      {:ok, Map.merge(params, %{active: true, token: access_token})}
    end
  end

  defp check_refresh_token({:ok, %{active: false, token: token} = params}, config) do
    refresh_token = AccessTokens.get_by_refresh_token(token, config)

    if refresh_token == nil || Revocable.is_revoked?(refresh_token) do
      {:ok, Map.merge(params, %{active: false})}
    else
      {:ok, Map.merge(params, %{active: true, token: refresh_token})}
    end
  end

  defp check_refresh_token({arg, params}, _config), do: {arg, params}

  defp build_response({:ok, %{active: false}}, _), do: {:ok, %{active: false}}

  defp build_response({:ok, %{active: true, token: token}}, config) do
    token = Config.repo(config).preload(token, :application)

    # as defined in https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
    # TODO: implement 'exp' and 'iat'
    {:ok,
     %{
       active: true,
       scope: token.scopes,
       token_type: "bearer",
       client_id: token.application.uid
     }}
  end
end
