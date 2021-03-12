defmodule ExOauth2Provider.Token.Utils do
  @moduledoc false

  alias ExOauth2Provider.{Applications, Utils.Error}

  @doc false
  @spec load_client({:ok, map()}, keyword()) :: {:ok, map()} | {:error, map()}
  def load_client({:ok, %{request: request = %{"client_id" => client_id}} = params}, config) do
    secret =
      case Map.get(request, "client_secret") do
        nil ->
          case Map.get(request, "code_verifier") do
            nil ->
              if request["grant_type"] == "refresh_token" do
                :refresh_token_flow
              else
                {:client_secret, ""}
              end

            code_verifier ->
              {:code_verifier, code_verifier}
          end

        client_secret ->
          {:client_secret, client_secret}
      end

    case Applications.load_application(client_id, secret, config) do
      nil -> Error.add_error({:ok, params}, Error.invalid_client())
      :invalid_code_verifier -> Error.add_error({:ok, params}, Error.invalid_request())
      client -> {:ok, Map.merge(params, %{client: client})}
    end
  end

  def load_client({:ok, params}, _config),
    do: Error.add_error({:ok, params}, Error.invalid_request())

  def load_client({:error, params}, _config), do: {:error, params}
end
