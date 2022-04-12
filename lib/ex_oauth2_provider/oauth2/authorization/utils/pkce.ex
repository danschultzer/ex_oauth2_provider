defmodule ExOauth2Provider.Authorization.Utils.Pkce do
  @moduledoc false
  alias ExOauth2Provider.Applications.Application

  @callback store(binary(), binary()) :: :ok
  @spec store(binary(), binary()) :: :ok
  def store(client_id, code_challenge) do
    if is_nil(Process.whereis(__MODULE__)) do
      {:ok, _pid} = Agent.start_link(fn -> client_id <> code_challenge end, name: __MODULE__)
      :ok
    else
      Agent.update(__MODULE__, fn _ -> client_id <> code_challenge end)
    end
  end

  @callback verify(Application.t(), binary(), code_challenge_method :: String.t()) ::
              :ok | {:error, String.t()}
  @spec verify(Application.t(), binary(), code_challenge_method :: String.t()) ::
          :ok | {:error, String.t()}
  def verify(application, code_verifier, code_challenge_method) do
    code_challenge = generate_code_challenge(code_verifier, code_challenge_method)

    if application.uid <> code_challenge == Agent.get(__MODULE__, & &1) do
      :ok
    else
      {:error, "invalid code verfier"}
    end
  end

  @doc """
  Generates a code challenge string given `code_verifier` and `code_challenge_method`.
  Supports "plain" and "S256" `code_challenge_method`.
  """
  @spec generate_code_challenge(code_verifier :: String.t(), code_challenge_method :: String.t()) ::
          String.t()
  def generate_code_challenge(code_verifier, "plain"), do: code_verifier

  def generate_code_challenge(code_verifier, "S256") do
    :sha256
    |> :crypto.hash(code_verifier)
    |> Base.url_encode64()
  end
end
