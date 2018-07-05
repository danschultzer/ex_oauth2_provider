defmodule ExOauth2Provider.Token.Utils do
  @moduledoc false

  alias ExOauth2Provider.{OauthApplications, Utils.Error}

  @doc false
  @spec load_client(map()) :: map()
  def load_client(%{request: request = %{"client_id" => client_id}} = params) do
    client_secret = Map.get(request, "client_secret", "")

    case OauthApplications.get_application(client_id, client_secret) do
      nil    -> Error.add_error(params, Error.invalid_client())
      client -> Map.merge(params, %{client: client})
    end
  end
  def load_client(params), do: Error.add_error(params, Error.invalid_request())
end
