defmodule ExOauth2Provider.Authorization.Util.Response do
  alias ExOauth2Provider.RedirectURI
  alias ExOauth2Provider.Scopes
  import ExOauth2Provider.Utils

  @doc false
  def preauthorize_response(%{client: client, request: %{"scope" => scopes}} = params) do
    case params do
      %{grant: grant} -> build_response(params, %{code: grant.token})
      %{error: error} -> build_response(params, error)
      _ -> {:ok, client, Scopes.to_list(scopes)}
    end
  end
  def preauthorize_response(%{error: error} = params),
    do: build_response(params, error)

  @doc false
  def authorize_response(%{} = params) do
    case params do
      %{grant: grant} -> build_response(params, %{code: grant.token})
      %{error: error} -> build_response(params, error)
    end
  end

  @doc false
  def deny_response(%{error: error} = params),
    do: build_response(params, error)

  @doc false
  defp build_response(%{request: request} = params, payload) do
    payload = add_state(payload, request)

    case can_redirect?(params) do
      true -> build_redirect_response(params, payload)
      _ -> build_standard_response(params, payload)
    end
  end

  @doc false
  defp add_state(payload, request) do
    case request["state"] do
      nil -> payload
      state ->
        %{"state" => state}
        |> Map.merge(payload)
        |> remove_empty_values
    end
  end

  @doc false
  defp build_redirect_response(%{request: %{"redirect_uri" => redirect_uri}}, payload) do
    case RedirectURI.native_uri?(redirect_uri) do
      true -> {:native_redirect, payload}
      _    -> {:redirect, RedirectURI.uri_with_query(redirect_uri, payload)}
    end
  end

  @doc false
  defp build_standard_response(%{grant: _}, payload) do
    {:ok, payload}
  end
  defp build_standard_response(%{error: error, error_http_status: error_http_status}, _) do
    {:error, error, error_http_status}
  end
  defp build_standard_response(%{error: error}, _) do # For DB errors
    {:error, error, :bad_request}
  end

  @doc false
  defp can_redirect?(%{error: %{error: error_name}, request: %{"redirect_uri" => redirect_uri}}) do
    error_name !== :invalid_redirect_uri &&
    error_name !== :invalid_client &&
    !RedirectURI.native_uri?(redirect_uri)
  end
  defp can_redirect?(%{error: _}), do: false
  defp can_redirect?(%{request: %{}}), do: true
end
