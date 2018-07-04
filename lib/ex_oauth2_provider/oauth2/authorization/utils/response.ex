defmodule ExOauth2Provider.Authorization.Utils.Response do
  @moduledoc false

  alias ExOauth2Provider.RedirectURI
  alias ExOauth2Provider.Scopes
  alias Ecto.Schema

  import ExOauth2Provider.Utils

  @doc false
  @spec error_response(map()) :: {:error, map(), integer()} |
                                 {:redirect, binary()} |
                                 {:native_redirect, %{code: binary()}}
  def error_response(%{error: error} = params),
    do: build_response(params, error)

  @doc false
  @spec preauthorize_response(map()) :: {:ok, Schema.t(), [binary()]} |
                                        {:error, map(), integer()} |
                                        {:redirect, binary()} |
                                        {:native_redirect, %{code: binary()}}
  def preauthorize_response(%{grant: grant} = params), do: build_response(params, %{code: grant.token})
  def preauthorize_response(%{error: error} = params), do: build_response(params, error)
  def preauthorize_response(%{client: client, request: %{"scope" => scopes}}), do: {:ok, client, Scopes.to_list(scopes)}

  @doc false
  @spec authorize_response(map()) :: {:ok, Schema.t(), [binary()]} |
                                     {:error, map(), integer()} |
                                     {:redirect, binary()} |
                                     {:native_redirect, %{code: binary()}}
  def authorize_response(%{grant: grant} = params), do: build_response(params, %{code: grant.token})
  def authorize_response(%{error: error} = params), do: build_response(params, error)

  @doc false
  @spec deny_response(map()) :: {:error, map(), integer()} |
                                {:redirect, binary()} |
                                {:native_redirect, %{code: binary()}}
  def deny_response(%{error: error} = params), do: build_response(params, error)

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
        |> remove_empty_values()
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
