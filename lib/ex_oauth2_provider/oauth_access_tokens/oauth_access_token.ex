defmodule ExOauth2Provider.OauthAccessTokens.OauthAccessToken do
  @moduledoc false

  @type t :: %__MODULE__{}

  use ExOauth2Provider.Schema
  alias ExOauth2Provider.{Config, OauthApplications.OauthApplication}

  schema "oauth_access_tokens" do
    belongs_to :resource_owner, Config.resource_owner_struct(:module), Config.resource_owner_struct(:options)
    belongs_to :application, OauthApplication, on_replace: :nilify

    field :token,         :string, null: false
    field :refresh_token, :string
    field :expires_in,    :integer
    field :revoked_at,    :naive_datetime, usec: true
    field :scopes,        :string
    field :previous_refresh_token, :string, null: false, default: ""

    timestamps()
  end
end
