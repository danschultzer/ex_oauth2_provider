defmodule ExOauth2Provider.Token.Utils do
  @moduledoc false

  alias ExOauth2Provider.{Applications, Utils.Error}

  @doc false
  @spec load_client({:ok, map()}, keyword()) :: {:ok, map()} | {:error, map()}
  def load_client(context, config, opts \\ [])

  def load_client(
        {:ok, %{request: request = %{"client_id" => client_id}} = params},
        config,
        opts
      ) do
    client_secret = Map.get(request, "client_secret", "")

    case Applications.load_application(client_id, client_secret, config) do
      nil -> Error.add_error({:ok, params}, Error.invalid_client(opts))
      client -> {:ok, Map.merge(params, %{client: client})}
    end
  end

  def load_client({:ok, params}, _config, _ops),
    do: Error.add_error({:ok, params}, Error.invalid_request())

  def load_client({:error, params}, _config, _opts), do: {:error, params}
  def load_client({:error, params, status}, _config, _opts), do: {:error, params, status}
end
