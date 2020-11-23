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

  @callback verify(Application.t(), binary()) :: boolean()
  @spec verify(Application.t(), binary()) :: boolean()
  def verify(application, code_verifier) do
    code_challenge = :crypto.hash(:sha256, code_verifier) |> Base.encode64()

    application.uid <> code_challenge == Agent.get(__MODULE__, & &1)
  end
end
