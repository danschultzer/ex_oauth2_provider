defmodule ExOauth2Provider.OauthAccessGrants.OauthAccessGrant do
  @moduledoc """
  Ecto schema for oauth access token grants
  """

  use Ecto.Schema
  alias ExOauth2Provider.OauthApplications.OauthApplication

  schema "oauth_access_grants" do
    belongs_to :resource_owner, ExOauth2Provider.resource_owner_model
    belongs_to :application, OauthApplication

    field :token,        :string,     null: false
    field :expires_in,   :integer,    null: false
    field :redirect_uri, :string,     null: false
    field :revoked_at,   :naive_datetime, usec: true
    field :scopes,       :string

    timestamps(updated_at: false)
  end
end
