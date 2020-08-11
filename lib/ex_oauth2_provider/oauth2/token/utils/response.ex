defmodule ExOauth2Provider.Token.Utils.Response do
  @moduledoc false

  alias ExOauth2Provider.Config

  @doc false
  @spec response({:ok, map()} | {:error, map()}, keyword()) ::
          {:ok, map()} | {:error, map(), atom()}
  def response({:ok, %{access_token: token}}, config),
    do: build_response(%{access_token: token}, config)

  def response({:error, %{error: _} = params}, config), do: build_response(params, config)

  @doc false
  @spec revocation_response({:ok, map()} | {:error, map()}, keyword()) ::
          {:ok, map()} | {:error, map(), atom()}
  def revocation_response({:error, %{should_return_error: true} = params}, config),
    do: response({:error, params}, config)

  def revocation_response({_any, _params}, _config), do: {:ok, %{}}

  defp build_response(%{access_token: access_token}, config) do
    body =
      %{
        access_token: access_token.token,
        # Access Token type: Bearer.
        # @see https://tools.ietf.org/html/rfc6750
        #   The OAuth 2.0 Authorization Framework: Bearer Token Usage
        token_type: "bearer",
        expires_in: access_token.expires_in,
        refresh_token: access_token.refresh_token,
        scope: access_token.scopes,
        created_at: access_token.inserted_at
      }
      |> customize_access_token_response(access_token, config)

    {:ok, body}
  end

  defp build_response(%{error: error, error_http_status: error_http_status}, _config) do
    {:error, error, error_http_status}
  end

  # For DB errors
  defp build_response(%{error: error}, _config) do
    {:error, error, :bad_request}
  end

  defp customize_access_token_response(response_body, access_token, config) do
    case Config.access_token_response_body_handler(config) do
      {module, method} -> apply(module, method, [response_body, access_token])
      _ -> response_body
    end
  end
end
