defmodule ExOauth2Provider.Authorization.Utils do
  @moduledoc """
  Utils for dealing with authorization requests.
  """

  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.Utils.Error
  alias ExOauth2Provider.Scopes

  @doc false
  def load_client(%{request: %{"client_id" => client_id}} = params) do
    case OauthApplications.get_application(client_id) do
      nil    -> Error.add_error(params, Error.invalid_client())
      client -> Map.merge(params, %{client: client})
    end
  end
  def load_client(params), do: Error.add_error(params, Error.invalid_request())

  @doc false
  def set_defaults(%{error: _} = params), do: params
  def set_defaults(%{request: request, client: client} = params) do
    redirect_uri = client.redirect_uri |> String.split |> Kernel.hd

    request = %{"redirect_uri" => redirect_uri, "scope" => Scopes.default_server_scopes |> Scopes.to_string}
    |> Map.merge(request)

    params
    |> Map.merge(%{request: request})
  end
end
