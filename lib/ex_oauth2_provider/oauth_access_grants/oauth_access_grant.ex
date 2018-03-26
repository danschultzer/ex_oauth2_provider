defmodule ExOauth2Provider.OauthAccessGrants.OauthAccessGrant do
  @moduledoc false

  use ExOauth2Provider.Schema
  alias ExOauth2Provider.OauthApplications.OauthApplication

  schema "oauth_access_grants" do
    belongs_to :resource_owner, ExOauth2Provider.Config.resource_owner_struct(), type: ExOauth2Provider.Config.resource_owner_struct().__schema__(:type, :id)
    belongs_to :application, OauthApplication

    field :token,        :string,     null: false
    field :expires_in,   :integer,    null: false
    field :redirect_uri, :string,     null: false
    field :revoked_at,   :naive_datetime, usec: true
    field :scopes,       :string

    timestamps(updated_at: false)
  end
end
