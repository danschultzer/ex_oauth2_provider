defmodule ExOauth2Provider.Utils.Validation do
  alias ExOauth2Provider.Scopes
  alias ExOauth2Provider.Utils.Error

  def validate_request({:ok, %{request: %{"scope" => scopes}, client: client} = params}, config) do
    scopes = Scopes.to_list(scopes)

    server_scopes =
      client.scopes
      |> Scopes.to_list()
      |> Scopes.default_to_server_scopes(config)

    case Scopes.all?(server_scopes, scopes) do
      true -> {:ok, params}
      false -> Error.add_error({:ok, params}, Error.invalid_scopes())
    end
  end

  def validate_request(error_response, _config), do: error_response

  def validate_required_query_params(%{request: request} = context, param_names) do
    missing =
      Enum.reject(
        param_names,
        fn name -> name in Map.keys(request) end
      )

    case missing do
      [] ->
        {:ok, context}

      missing ->
        Error.invalid_request("Missing required param #{Enum.join(missing, ", ")}")
    end
  end

  # This can't be included in the required params because it simply checks
  # presence and is done before you try to load any records. This requires
  # the client_id and the record to be loaded already.
  def validate_scope({:ok, context}) do
    %{client: application, config: config, request: request} = context

    scopes =
      request
      |> Map.get("scope")
      |> Scopes.to_list()

    server_scopes =
      application.scopes
      |> Scopes.to_list()
      |> Scopes.default_to_server_scopes(config)

    case Scopes.all?(server_scopes, scopes) do
      true -> {:ok, context}
      false -> Error.invalid_scopes(:bad_request)
    end
  end

  def validate_scope(error_response), do: error_response
end
