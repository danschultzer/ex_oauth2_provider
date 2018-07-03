defmodule ExOauth2Provider.Authorization.Utils.Helpers do
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.RedirectURI
  alias ExOauth2Provider.Utils.Error
  alias ExOauth2Provider.Scopes

  def check_previous_authorization(%{error: _error} = params), do: params

  def check_previous_authorization(
        %{resource_owner: resource_owner, client: application, request: %{"scope" => scopes}} =
          params
      ) do
    case OauthAccessTokens.get_matching_token_for(resource_owner, application, scopes) do
      nil -> params
      token -> Map.put(params, :access_token, token)
    end
  end

  def validate_request(%{error: _error} = params), do: params

  def validate_request(%{request: _request, client: _client} = params) do
    params
    |> validate_resource_owner()
    |> validate_redirect_uri()
    |> validate_scopes()
  end

  defp validate_resource_owner(%{error: _error} = params), do: params

  defp validate_resource_owner(%{resource_owner: resource_owner} = params) do
    case resource_owner do
      %{__struct__: _} -> params
      _ -> Error.add_error(params, Error.invalid_request())
    end
  end

  defp validate_scopes(%{error: _} = params), do: params

  defp validate_scopes(%{request: %{"scope" => scopes}, client: client} = params) do
    scopes = scopes |> Scopes.to_list()
    server_scopes = client.scopes |> Scopes.to_list() |> Scopes.default_to_server_scopes()

    case Scopes.all?(server_scopes, scopes) do
      true -> params
      false -> Error.add_error(params, Error.invalid_scopes())
    end
  end

  defp validate_redirect_uri(%{error: _} = params), do: params

  defp validate_redirect_uri(
         %{request: %{"redirect_uri" => redirect_uri}, client: client} = params
       ) do
    cond do
      RedirectURI.native_redirect_uri?(redirect_uri) ->
        params

      RedirectURI.valid_for_authorization?(redirect_uri, client.redirect_uri) ->
        params

      true ->
        Error.add_error(params, Error.invalid_redirect_uri())
    end
  end

  defp validate_redirect_uri(params), do: Error.add_error(params, Error.invalid_request())
end
