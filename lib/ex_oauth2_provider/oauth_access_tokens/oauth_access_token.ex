defmodule ExOauth2Provider.OauthAccessTokens.OauthAccessToken do
  @moduledoc false

  use ExOauth2Provider.Schema
  alias ExOauth2Provider.OauthApplications.OauthApplication
  alias ExOauth2Provider.{Config, Utils}

  @resource_owner_struct Config.resource_owner_struct()
  @resource_owner_belongs_to_opts Utils.schema_belongs_to_opts(@resource_owner_struct)

  schema "oauth_access_tokens" do
    belongs_to :application, OauthApplication, on_replace: :nilify
    belongs_to :resource_owner, @resource_owner_struct, @resource_owner_belongs_to_opts

    field :token,         :string, null: false
    field :refresh_token, :string
    field :expires_in,    :integer
    field :revoked_at,    :naive_datetime, usec: true
    field :scopes,        :string
    field :previous_refresh_token, :string, null: false, default: ""

    timestamps()
  end
end
