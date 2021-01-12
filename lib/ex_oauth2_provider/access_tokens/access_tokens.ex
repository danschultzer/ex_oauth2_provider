defmodule ExOauth2Provider.AccessTokens do
  @moduledoc """
  Defines a behaviour for interacting with an access_token.
  """

  alias Ecto.Schema
  alias ExOauth2Provider.Config

  @callback revoke(Schema.t(), keyword()) :: {:ok, Schema.t()} | {:error, Changeset.t()}
  def revoke(schema, config \\ []), do: strategy(config).revoke(schema, config)

  @callback revoke!(Schema.t(), keyword()) :: Schema.t() | no_return
  def revoke!(schema, config \\ []), do: strategy(config).revoke!(schema, config)

  @callback is_expired?(Schema.t() | nil, keyword()) :: boolean()
  def is_expired?(token, config \\ []), do: strategy(config).is_expired?(token)

  @callback is_revoked?(Schema.t(), keyword()) :: boolean()
  def is_revoked?(token, config \\ []), do: strategy(config).is_revoked?(token)

  @callback get_by_token(binary(), keyword()) :: AccessToken.t() | nil
  def get_by_token(token, config \\ []), do: strategy(config).get_by_token(token, config)

  @callback get_by_refresh_token(binary(), keyword()) :: AccessToken.t() | nil
  def get_by_refresh_token(refresh_token, config \\ []),
    do: strategy(config).get_by_refresh_token(refresh_token, config)

  @callback get_by_refresh_token_for(Application.t(), binary(), keyword()) ::
              AccessToken.t() | nil
  def get_by_refresh_token_for(application, refresh_token, config \\ []),
    do: strategy(config).get_by_refresh_token_for(application, refresh_token, config)

  @callback get_token_for(Schema.t(), Application.t(), binary(), keyword()) ::
              AccessToken.t() | nil
  def get_token_for(resource_owner, application, scopes, config \\ []),
    do: strategy(config).get_token_for(resource_owner, application, scopes, config)

  @spec get_all_tokens_for(Schema.t(), Application.t(), keyword()) :: any
  def get_all_tokens_for(resource_owner, application, config \\ []),
    do: strategy(config).get_all_tokens_for(resource_owner, application, config)

  @callback get_application_token_for(Application.t(), binary(), keyword()) ::
              AccessToken.t() | nil
  def get_application_token_for(application, scopes, config \\ []),
    do: strategy(config).get_application_token_for(application, scopes, config)

  @callback get_authorized_tokens_for(Schema.t(), keyword()) :: [AccessToken.t()]
  def get_authorized_tokens_for(resource_owner, config \\ []),
    do: strategy(config).get_authorized_tokens_for(resource_owner, config)

  @callback create_token(Schema.t() | integer() | Ecto.UUID.t(), map(), keyword()) ::
              {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def create_token(resource_owner, attrs \\ %{}, config \\ []),
    do: strategy(config).create_token(resource_owner, attrs, config)

  @callback create_application_token(Schema.t() | nil, map(), keyword()) ::
              {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def create_application_token(application, attrs \\ %{}, config \\ []),
    do: strategy(config).create_application_token(application, attrs, config)

  @callback is_accessible?(AccessToken.t() | nil) :: boolean()
  def is_accessible?(token, config \\ []), do: strategy(config).is_accessible?(token)

  @callback get_by_previous_refresh_token_for(AccessToken.t(), keyword()) :: AccessToken.t() | nil
  def get_by_previous_refresh_token_for(token, config \\ []),
    do: strategy(config).get_by_previous_refresh_token_for(token, config)

  @callback revoke_previous_refresh_token(AccessToken.t()) ::
              {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def revoke_previous_refresh_token(access_token, config \\ []),
    do: strategy(config).revoke_previous_refresh_token(access_token, config)

  @callback get_resource_owner_for(Schema.t(), keyword()) :: Schema.t()
  def get_resource_owner_for(access_token, config \\ []),
    do: strategy(config).get_resource_owner_for(access_token, config)

  defp strategy(config), do: Config.access_token_strategy(config)
end
