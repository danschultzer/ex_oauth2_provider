defmodule ExOauth2Provider.Authorization.Utils do
  @moduledoc false

  alias ExOauth2Provider.{Applications, Utils.Error}
  alias Ecto.Schema

  @doc false
  @spec prehandle_request(Schema.t(), map()) :: {:ok, map()} | {:error, map()}
  def prehandle_request(resource_owner, request) do
    resource_owner
    |> new_params(request)
    |> load_client()
    |> set_defaults()
  end

  defp new_params(resource_owner, request) do
    {:ok, %{resource_owner: resource_owner, request: request}}
  end

  defp load_client({:ok, %{request: %{"client_id" => client_id}} = params}) do
    case Applications.get_application(client_id) do
      nil    -> Error.add_error({:ok, params}, Error.invalid_client())
      client -> {:ok, Map.put(params, :client, client)}
    end
  end
  defp load_client({:ok, params}), do: Error.add_error({:ok, params}, Error.invalid_request())

  defp set_defaults({:error, params}), do: {:error, params}
  defp set_defaults({:ok, %{request: request, client: client} = params}) do
    [redirect_uri | _rest] = String.split(client.redirect_uri)

    request = Map.new()
    |> Map.put("redirect_uri", redirect_uri)
    |> Map.put("scope", nil)
    |> Map.merge(request)

    {:ok, Map.put(params, :request, request)}
  end
end
