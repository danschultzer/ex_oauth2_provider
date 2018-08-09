defmodule ExOauth2Provider.OauthAccessGrants.OauthAccessGrant do
  @moduledoc false

  @type t :: %__MODULE__{}

  use ExOauth2Provider.Schema
  alias ExOauth2Provider.{Config, OauthApplications.OauthApplication}

  schema "oauth_access_grants" do
    belongs_to :resource_owner, Config.resource_owner_struct(:module), Config.resource_owner_struct(:options)
    belongs_to :application, OauthApplication

    field :token,        :string,     null: false
    field :expires_in,   :integer,    null: false
    field :redirect_uri, :string,     null: false
    field :revoked_at,   :naive_datetime, usec: true
    field :scopes,       :string

    timestamps(updated_at: false)
  end
end
