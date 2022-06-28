defmodule ExOauth2Provider.Token.DeviceCode do
  alias ExOauth2Provider.{AccessTokens, Config, DeviceGrants}
  alias ExOauth2Provider.Token.Utils
  alias ExOauth2Provider.Utils.{Error, Validation}

  @required_params ~w(client_id device_code)

  # Device Access Token Request
  # https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
  #
  # NOTE: http error status for invalid_client in a token response  should be
  # 401, not 422 which is the value provided in Error#invalid_client.
  # This overrides that so we get the expected behavior.
  # https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
  def grant(request, config \\ []) do
    %{config: config, request: request}
    |> Validation.validate_required_query_params(@required_params)
    |> Utils.load_client(config, error_http_status: :unauthorized)
    |> Validation.validate_scope()
    |> load_grant()
    |> check_expiration()
    |> check_polling_rate()
    |> check_authorization()
    |> create_token()
    |> send_response()
  end

  defp send_response({:ok, %{access_token: access_token}}) do
    {
      :ok,
      %{
        access_token: access_token.token,
        expires: access_token.expires_in,
        refresh_token: access_token.refresh_token,
        scope: access_token.scopes,
        token_type: "bearer"
      }
    }
  end

  defp send_response(error_response), do: error_response

  defp create_token({:ok, context}) do
    %{config: config, grant: grant} = context

    result =
      Config.repo(config).transaction(fn ->
        grant
        |> DeviceGrants.delete!(config)
        |> find_or_create_token(context)
      end)

    case result do
      {:ok, {:error, error}} -> Error.add_error({:ok, context}, error)
      {:ok, {:ok, access_token}} -> {:ok, Map.put(context, :access_token, access_token)}
      {:error, error} -> Error.add_error({:ok, context}, error)
    end
  end

  defp create_token(error_response), do: error_response

  defp check_authorization({:ok, %{grant: %{user_code: nil}} = context}) do
    {:ok, context}
  end

  defp check_authorization({:ok, %{grant: %{user_code: _user_code}}}) do
    {:error, %{error: :authorization_pending}, :bad_request}
  end

  defp check_authorization(error_response), do: error_response

  defp check_expiration({:ok, %{config: config, grant: grant} = context}) do
    too_old =
      DateTime.utc_now()
      |> DateTime.add(-grant.expires_in, :second)
      |> DateTime.truncate(:second)

    inserted_at = DateTime.from_naive!(grant.inserted_at, "Etc/UTC")

    case inserted_at > too_old do
      false ->
        DeviceGrants.delete!(grant, config)
        {:error, %{error: :expired_token}, :bad_request}

      true ->
        {:ok, context}
    end
  end

  defp check_expiration(error_response), do: error_response

  defp check_polling_rate({:ok, %{config: config, grant: grant} = context}) do
    # NOTE: The DeviceGrant struct has seconds precision.
    age_limit =
      DateTime.utc_now()
      |> DateTime.add(-Config.device_flow_polling_interval(config), :second)
      |> DateTime.truncate(:second)

    too_fast = grant.last_polled_at && grant.last_polled_at >= age_limit

    DeviceGrants.update_last_polled_at!(grant, config)

    case too_fast do
      true -> {:error, %{error: :slow_down}, :bad_request}
      nil -> {:ok, context}
      false -> {:ok, context}
    end
  end

  defp check_polling_rate(error_response), do: error_response

  defp find_or_create_token(deleted_grant, context) do
    %{client: application, config: config, request: request} = context
    scopes = Map.get(request, "scope", nil)

    token_params = %{
      application: application,
      scopes: scopes,
      use_refresh_token: Config.use_refresh_token?(config)
    }

    deleted_grant.resource_owner
    |> AccessTokens.get_token_for(application, scopes, config)
    |> case do
      nil -> AccessTokens.create_token(deleted_grant.resource_owner, token_params, config)
      access_token -> {:ok, access_token}
    end
  end

  defp load_grant({:ok, context}) do
    %{client: client, config: config, request: request} = context
    device_code = Map.get(request, "device_code")

    client
    |> DeviceGrants.find_by_application_and_device_code(device_code, config)
    |> Config.repo(config).preload(:application)
    |> Config.repo(config).preload(:resource_owner)
    |> case do
      nil -> Error.invalid_grant(:bad_request)
      grant -> {:ok, Map.put(context, :grant, grant)}
    end
  end

  # NOTE: This is from Utils.load_client failure.
  # It joins the status to the context.
  defp load_grant({:error, %{error: error, error_http_status: status}}) do
    {:error, error, status}
  end

  defp load_grant({:error, error, status}), do: {:error, error, status}
end
