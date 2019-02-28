defmodule ExOauth2Provider.Authorization.Utils.Response do
  @moduledoc false

  alias ExOauth2Provider.{RedirectURI, Scopes, Utils}
  alias Ecto.Schema

  @type native_redirect :: {:native_redirect, %{code: binary()}}
  @type redirect :: {:redirect, binary()}
  @type error :: {:error, map(), integer()}
  @type success :: {:ok, Schema.t(), [binary()]}

  @doc false
  @spec error_response({:error, map()}) :: error() | redirect() | native_redirect()
  def error_response({:error, %{error: error} = params}), do: build_response(params, error)

  @doc false
  @spec preauthorize_response({:ok, map()} | {:error, map()}) :: success() | error() | redirect() | native_redirect()
  def preauthorize_response({:ok, %{grant: grant} = params}), do: build_response(params, %{code: grant.token})
  def preauthorize_response({:ok, %{client: client, request: %{"scope" => scopes}}}), do: {:ok, client, Scopes.to_list(scopes)}
  def preauthorize_response({:error, %{error: error} = params}), do: build_response(params, error)

  @doc false
  @spec authorize_response({:ok, map()} | {:error, map()}) :: success() | error() | redirect() | native_redirect()
  def authorize_response({:ok, %{grant: grant} = params}), do: build_response(params, %{code: grant.token})
  def authorize_response({:error, %{error: error} = params}), do: build_response(params, error)

  @doc false
  @spec deny_response({:error, map()}) :: error() | redirect() | native_redirect()
  def deny_response({:error, %{error: error} = params}), do: build_response(params, error)

  defp build_response(%{request: request} = params, payload) do
    payload = add_state(payload, request)

    case can_redirect?(params) do
      true -> build_redirect_response(params, payload)
      _    -> build_standard_response(params, payload)
    end
  end

  defp add_state(payload, request) do
    case request["state"] do
      nil ->
        payload

      state ->
        %{"state" => state}
        |> Map.merge(payload)
        |> Utils.remove_empty_values()
    end
  end

  defp build_redirect_response(%{request: %{"redirect_uri" => redirect_uri}}, payload) do
    case RedirectURI.native_redirect_uri?(redirect_uri) do
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

  defp can_redirect?(%{error: %{error: :invalid_redirect_uri}}), do: false
  defp can_redirect?(%{error: %{error: :invalid_client}}), do: false
  defp can_redirect?(%{error: %{error: _error}, request: %{"redirect_uri" => redirect_uri}}), do: !RedirectURI.native_redirect_uri?(redirect_uri)
  defp can_redirect?(%{error: _}), do: false
  defp can_redirect?(%{request: %{}}), do: true
end
