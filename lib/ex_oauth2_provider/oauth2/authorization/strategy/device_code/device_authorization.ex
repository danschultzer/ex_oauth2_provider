defmodule ExOauth2Provider.Authorization.DeviceCode.DeviceAuthorization do
  alias ExOauth2Provider.{
    Config,
    DeviceGrants,
    Authorization.Utils,
    Utils.DeviceFlow,
    Utils.Error,
    Utils.Validation
  }

  @required_params ~w(client_id)

  # Device Authorization Request
  # https://tools.ietf.org/html/rfc8628#section-3.1
  def process_request(request, config \\ []) do
    %{config: config, request: request}
    |> Validation.validate_required_query_params(@required_params)
    |> load_application()
    |> Validation.validate_scope()
    |> issue_grant()
    |> send_response()
  end

  def send_response({:ok, %{config: config, grant: grant}}) do
    payload = %{
      device_code: grant.device_code,
      expires_in: grant.expires_in,
      interval: Config.device_flow_polling_interval(config),
      user_code: grant.user_code,
      verification_uri: Config.device_flow_verification_uri(config)
    }

    {:ok, payload}
  end

  def send_response({:error, %{error: error, error_http_status: http_status}}) do
    {:error, error, http_status}
  end

  def send_response({:error, error, http_status}) do
    {:error, error, http_status}
  end

  defp generate_grant_params(request, config) do
    %{
      device_code: DeviceFlow.generate_device_code(),
      expires_in: Config.authorization_code_expires_in(config),
      scopes: Map.get(request, "scope"),
      user_code: DeviceFlow.generate_user_code()
    }
  end

  defp issue_grant({:ok, context}) do
    %{client: application, config: config, request: request} = context

    # This is just basic cleanup.
    DeviceGrants.delete_expired(config)

    grant_params = generate_grant_params(request, config)

    case DeviceGrants.create_grant(application, grant_params, config) do
      {:ok, grant} -> {:ok, Map.put(context, :grant, grant)}
      {:error, error} -> Error.add_error({:ok, context}, error)
    end
  end

  defp issue_grant(error_response), do: error_response

  defp load_application({:ok, %{config: config, request: request}}) do
    # There is no resource owner on this request so we explicitly pass nil.
    # This pre-handler is constructing a new map based on request so we need
    # to stitch back in config. Since we pre-validate the required params
    # and have a context before this runs it's easier this way until it can be
    # refactored to work on a pre-made context.
    {ok_or_error, context} =
      Utils.prehandle_request(
        nil,
        request,
        config,
        error_http_status: :unauthorized
      )

    {ok_or_error, Map.put(context, :config, config)}
  end

  defp load_application(error_response), do: error_response
end
