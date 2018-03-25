defmodule ExOauth2Provider.Token.Utils do
  @moduledoc false

  alias ExOauth2Provider.OauthApplications
  alias ExOauth2Provider.OauthAccessTokens
  alias ExOauth2Provider.OauthAccessGrants.OauthAccessGrant
  alias ExOauth2Provider.Utils.Error

  @doc false
  @spec load_client(Map.t) :: Map.t
  def load_client(%{request: request = %{"client_id" => client_id}} = params) do
    client_secret = Map.get(request, "client_secret", "")

    case OauthApplications.get_application(client_id, client_secret) do
      nil    -> Error.add_error(params, Error.invalid_client())
      client -> Map.merge(params, %{client: client})
    end
  end
  def load_client(params), do: Error.add_error(params, Error.invalid_request())

  @doc false
  @spec find_or_create_access_token({:error, term}, Map.t) :: {:error, term}
  @spec find_or_create_access_token({:ok, %OauthAccessGrant{}}, Map.t) :: {:ok, %OauthAccessTokens.OauthAccessToken{}} | {:error, Ecto.Changeset.t}
  @spec find_or_create_access_token(Ecto.Schema.t, Map.t) :: {:ok, %OauthAccessTokens.OauthAccessToken{}} | {:error, Ecto.Changeset.t}
  def find_or_create_access_token({:error, _} = error, _), do: error
  def find_or_create_access_token({:ok, %OauthAccessGrant{} = access_grant}, token_params),
    do: find_or_create_access_token(access_grant.resource_owner, token_params)
  def find_or_create_access_token(resource_owner, token_params) do
    token_params = %{expires_in: ExOauth2Provider.Config.access_token_expires_in} |> Map.merge(token_params)
    OauthAccessTokens.get_or_create_token(resource_owner, token_params)
  end
end
