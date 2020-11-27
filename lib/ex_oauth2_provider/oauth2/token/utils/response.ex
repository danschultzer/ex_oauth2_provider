defmodule ExOauth2Provider.Token.Utils.Response do
  @moduledoc false

  alias ExOauth2Provider.Config

  @doc false
  @spec response({:ok, map()} | {:error, map()}, keyword()) ::
          {:ok, map()} | {:error, map(), atom()}
  def response({:ok, params = %{access_token: _access_token}}, config),
    do: build_response(params, config)

  def response({:error, %{error: _} = params}, config), do: build_response(params, config)

  @doc false
  @spec revocation_response({:ok, map()} | {:error, map()}, keyword()) ::
          {:ok, map()} | {:error, map(), atom()}
  def revocation_response({:error, %{should_return_error: true} = params}, config),
    do: response({:error, params}, config)

  def revocation_response({_any, _params}, _config), do: {:ok, %{}}

  defp build_response(params = %{access_token: access_token}, config) do
    except_fields = Config.access_token_except_fields(config)

    access_grant = Map.get(params, :access_grant)

    body =
      [{:access_token, :token}, :expires_in, :refresh_token, :scope, :created_at]
      |> Enum.map(fn
        {key, search_key} ->
          if search_key not in except_fields, do: {key, search_key}

        search_key ->
          if search_key not in except_fields, do: search_key
      end)
      |> Enum.map(fn
        {key, search_key} ->
          {key, Map.get(access_token, search_key)}

        search_key ->
          {search_key, Map.get(access_token, search_key)}
      end)
      # Access Token type: Bearer.
      # @see https://tools.ietf.org/html/rfc6750
      #   The OAuth 2.0 Authorization Framework: Bearer Token Usage
      |> Enum.into(%{token_type: "bearer"})
      |> customize_access_token_response(access_token, access_grant, config)

    {:ok, body}
  end

  defp build_response(%{error: error, error_http_status: error_http_status}, _config) do
    {:error, error, error_http_status}
  end

  # For DB errors
  defp build_response(%{error: error}, _config) do
    {:error, error, :bad_request}
  end

  defp customize_access_token_response(response_body, access_token, access_grant, config) do
    case Config.access_token_response_body_handler(config) do
      {module, method} -> apply(module, method, [response_body, access_token, access_grant])
      _ -> response_body
    end
  end
end
