defmodule ExOauth2Provider.OauthAccessTokens.OauthAccessToken do
  @moduledoc """
  Ecto schema for oauth access tokens
  """

  use Ecto.Schema
  alias ExOauth2Provider.OauthApplications.OauthApplication

  schema "oauth_access_tokens" do
    belongs_to :application, OauthApplication, on_replace: :nilify
    belongs_to :resource_owner, ExOauth2Provider.resource_owner_struct

    field :token,         :string, null: false
    field :refresh_token, :string
    field :expires_in,    :integer
    field :revoked_at,    :naive_datetime, usec: true
    field :scopes,        :string

    if ExOauth2Provider.refresh_token_revoked_on_use? do
      field :previous_refresh_token, :string, null: false, default: ""
    end

    timestamps()
  end
end
