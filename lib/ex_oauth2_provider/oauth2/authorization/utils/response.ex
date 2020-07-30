defmodule ExOauth2Provider.Authorization.Utils.Response do
  @moduledoc false

  alias ExOauth2Provider.{Config, RedirectURI, Scopes, Utils}
  alias Ecto.Schema

  @type native_redirect :: {:native_redirect, %{code: binary()}}
  @type redirect :: {:redirect, binary()}
  @type error :: {:error, map(), integer()}
  @type success :: {:ok, Schema.t(), [binary()]}

  @doc false
  @spec error_response({:error, map()}, keyword()) :: error() | redirect() | native_redirect()
  def error_response({:error, %{error: error} = params}, config), do: build_response(params, error, config)

  @doc false
  @spec preauthorize_response({:ok, map()} | {:error, map()}, keyword()) :: success() | error() | redirect() | native_redirect()
  def preauthorize_response({:ok, %{grant: grant} = params}, config), do: build_response(params, %{code: grant.token}, config)
  def preauthorize_response({:ok, %{client: client, request: %{"scope" => scopes}}}, _config), do: {:ok, client, Scopes.to_list(scopes)}
  def preauthorize_response({:error, %{error: error} = params}, config), do: build_response(params, error, config)

  @doc false
  @spec authorize_response({:ok, map()} | {:error, map()}, keyword()) :: success() | error() | redirect() | native_redirect()
  def authorize_response({:ok, %{grant: grant} = params}, config), do: build_response(params, %{code: grant.token}, config)
  def authorize_response({:error, %{error: error} = params}, config), do: build_response(params, error, config)

  @doc false
  @spec deny_response({:error, map()}, keyword()) :: error() | redirect() | native_redirect()
  def deny_response({:error, %{error: error} = params}, config), do: build_response(params, error, config)

  defp build_response(%{request: request} = params, payload, config) do
    payload = add_params(payload, request, config)

    case can_redirect?(params, config) do
      true -> build_redirect_response(params, payload, config)
      _    -> build_standard_response(params, payload)
    end
  end

  defp add_params(payload, request, config) do
    keys = Config.response_params(config)

    request
    |> Map.take(keys)
    |> Map.merge(payload)
    |> Utils.remove_empty_values()
  end

  defp build_redirect_response(%{request: %{"redirect_uri" => redirect_uri}}, payload, config) do
    case RedirectURI.native_redirect_uri?(redirect_uri, config) do
      true -> {:native_redirect, payload}
      _    -> {:redirect, RedirectURI.uri_with_query(redirect_uri, payload)}
    end
  end

  defp build_standard_response(%{grant: _}, payload) do
    {:ok, payload}
  end
  defp build_standard_response(%{error: error, error_http_status: error_http_status}, _) do
    {:error, error, error_http_status}
  end
  defp build_standard_response(%{error: error}, _) do # For DB errors
    {:error, error, :bad_request}
  end

  defp can_redirect?(%{error: %{error: :invalid_redirect_uri}}, _config), do: false
  defp can_redirect?(%{error: %{error: :invalid_client}}, _config), do: false
  defp can_redirect?(%{error: %{error: _error}, request: %{"redirect_uri" => redirect_uri}}, config), do: !RedirectURI.native_redirect_uri?(redirect_uri, config)
  defp can_redirect?(%{error: _}, _config), do: false
  defp can_redirect?(%{request: %{}}, _config), do: true
end
