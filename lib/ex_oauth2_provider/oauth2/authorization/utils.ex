defmodule ExOauth2Provider.Authorization.Utils do
  @moduledoc false

  alias ExOauth2Provider.{OauthApplications, Utils.Error}
  alias Ecto.Schema

  @doc false
  @spec prehandle_request(Schema.t(), map()) :: map()
  def prehandle_request(resource_owner, request) do
    %{resource_owner: resource_owner,
      request: request}
    |> load_client()
    |> set_defaults()
  end

  defp load_client(%{request: %{"client_id" => client_id}} = params) do
    case OauthApplications.get_application(client_id) do
      nil    -> Error.add_error(params, Error.invalid_client())
      client -> Map.put(params, :client, client)
    end
  end
  defp load_client(params), do: Error.add_error(params, Error.invalid_request())

  defp set_defaults(%{error: _} = params), do: params
  defp set_defaults(%{request: request, client: client} = params) do
    [redirect_uri | _rest] = String.split(client.redirect_uri)

    request = Map.new()
    |> Map.put("redirect_uri", redirect_uri)
    |> Map.put("scope", nil)
    |> Map.merge(request)

    Map.put(params, :request, request)
  end
end
