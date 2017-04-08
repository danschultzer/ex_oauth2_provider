defmodule ExOauth2Provider.Token.Utils do
  @moduledoc """
  Utils for dealing with token requests.
  """

  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessGrants.OauthAccessGrant
  alias ExOauth2Provider.Token.Utils
  alias ExOauth2Provider.Utils.Error

  @doc false
  def load_client(%{request: %{"client_id" => client_id, "client_secret" => client_secret}} = params) do
    case OauthApplications.get_application(client_id, client_secret) do
      nil    -> Error.add_error(params, Error.invalid_client())
      client -> Map.merge(params, %{client: client})
    end
  end
  def load_client(params), do: Error.add_error(params, Error.invalid_request())

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
end
