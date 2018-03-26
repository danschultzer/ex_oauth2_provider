defmodule ExOauth2Provider.OauthAccessGrants.OauthAccessGrant do
  @moduledoc false

  use ExOauth2Provider.Schema
  alias ExOauth2Provider.OauthApplications.OauthApplication
  alias ExOauth2Provider.{Config, Utils}

  @resource_owner_struct Config.resource_owner_struct()
  @resource_owner_belongs_to_opts Utils.schema_belongs_to_opts(@resource_owner_struct)

  schema "oauth_access_grants" do
    belongs_to :resource_owner, @resource_owner_struct, @resource_owner_belongs_to_opts
    belongs_to :application, OauthApplication

    field :token,        :string,     null: false
    field :expires_in,   :integer,    null: false
    field :redirect_uri, :string,     null: false
    field :revoked_at,   :naive_datetime, usec: true
    field :scopes,       :string

    timestamps(updated_at: false)
  end
end
