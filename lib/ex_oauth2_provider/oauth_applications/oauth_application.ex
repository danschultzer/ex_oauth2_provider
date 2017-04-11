defmodule ExOauth2Provider.OauthApplications.OauthApplication do
  @moduledoc false

  use Ecto.Schema
  require Logger

  # For Phoenix integrations
  if Code.ensure_loaded?(Phoenix.Param) do
    @derive {Phoenix.Param, key: :uid}
  end

  schema "oauth_applications" do
    if is_nil(ExOauth2Provider.Config.application_owner_struct()) do
      Logger.error("You need to set a resource_owner or application_owner in your config and recompile ex_oauth2_provider!")
    end

    belongs_to :owner, ExOauth2Provider.Config.application_owner_struct()

    field :name,         :string,     null: false
    field :uid,          :string,     null: false
    field :secret,       :string,     null: false
    field :redirect_uri, :string,     null: false
    field :scopes,       :string,     null: false, default: ""

    has_many :access_tokens, ExOauth2Provider.OauthAccessTokens.OauthAccessToken

    timestamps()
  end
end
