defmodule ExOauth2Provider.Token.Util do
  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessGrants.OauthAccessGrant
  alias ExOauth2Provider.Token.Util
  alias ExOauth2Provider.Token.Util.Error

  @doc false
  def load_client(%{request: %{"client_id" => client_id, "client_secret" => client_secret}} = params) do
    case OauthApplications.get_application(client_id, client_secret) do
      nil    -> Util.add_error(params, Error.invalid_client())
      client -> Map.merge(params, %{client: client})
    end
  end
  def load_client(params), do: add_error(params, Error.invalid_request())

  @doc false
  def create_access_token({:error, _} = error, _), do: error
  def create_access_token({:ok, %OauthAccessGrant{} = access_grant}, token_params),
    do: create_access_token(access_grant.resource_owner, token_params)
  # def create_access_token({:ok, %AccessTokens.AccessToken{} = access_token}, token_params),
  #   do: create_access_token(access_token.resource_owner, token_params)
  def create_access_token(%{id: _} = resource_owner, token_params) do
    token_params = %{expires_in: ExOauth2Provider.access_token_expires_in}
                   |> Map.merge(token_params)
    OauthAccessTokens.find_or_create_token(resource_owner, token_params)
  end

  @doc false
  def add_error(%{error: _} = params, _), do: params
  def add_error(params, {:error, error, http_status}) do
    Map.merge(params, %{error: error, error_http_status: http_status})
  end
end
