defmodule ExOauth2Provider.Authorization.DeviceCode.UserInteraction do
  alias Ecto.Changeset
  alias ExOauth2Provider.DeviceGrants

  @message_lookup [
    expired_user_code: "The user_code has expired.",
    invalid_owner: "The given owner is invalid.",
    invalid_user_code: "The user_code is invalid.",
    user_code_missing: "The request is missing the required param user_code."
  ]
  @status_lookup [
    expired_user_code: :unprocessable_entity,
    invalid_owner: :unprocessable_entity,
    invalid_user_code: :unprocessable_entity,
    user_code_missing: :bad_request
  ]

  # User Interaction Request - approve the grant with user code
  # https://datatracker.ietf.org/doc/html/rfc8628#section-3.3
  def process_request(owner, request, config \\ []) do
    %{config: config, owner: owner, user_code: Map.get(request, "user_code")}
    |> find_device_grant()
    |> authorize()
    |> send_response()
  end

  defp authorize({:error, _code} = error), do: error
  defp authorize(%{grant: nil}), do: {:error, :invalid_user_code}

  defp authorize(%{config: config, grant: grant, owner: owner}) do
    if DeviceGrants.is_expired?(grant) do
      {:error, :expired_user_code}
    else
      DeviceGrants.authorize(grant, owner, config)
    end
  end

  defp find_device_grant(%{user_code: nil}) do
    {:error, :user_code_missing}
  end

  defp find_device_grant(%{config: config, user_code: user_code} = context) do
    Map.put(context, :grant, DeviceGrants.find_by_user_code(user_code, config))
  end

  defp send_response({:error, %Changeset{}}) do
    send_response({:error, :invalid_owner})
  end

  defp send_response({:error, code}) do
    message = Keyword.get(@message_lookup, code)
    status = Keyword.get(@status_lookup, code)

    {:error, %{error: code, error_description: message}, status}
  end

  defp send_response({:ok, device_grant}) do
    {:ok, device_grant}
  end
end
